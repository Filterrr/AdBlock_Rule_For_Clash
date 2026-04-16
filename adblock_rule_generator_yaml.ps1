# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，高效拉取去重，自动清理冗余父子域名
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0

# === 自定义需要强制放行拦截的白名单域名 ===
$customExcludedDomains = @(
    # "example.com",
    # "taobao.com"
)

# 定义广告过滤器URL列表
$urlList = @(
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "https://raw.githubusercontent.com/Filterrr/AdBlock_Rule_For_Clash/main/allowlist.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylist.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt"
)

# 日志文件路径
$logFilePath = "$PSScriptRoot/adblock_log.txt"
Clear-Content -Path $logFilePath -ErrorAction SilentlyContinue

# 日志输出函数
function Write-Log($message) {
    Write-Host $message
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
}

Write-Log "开始拉取并转换广告拦截规则..."

# 创建 HashSet 存储规则和排除的域名，使用 OrdinalIgnoreCase 忽略大小写，极大提高查找效率
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# 录入手动定义的预设全局强制白名单
foreach ($cd in $customExcludedDomains) {
    $excludedDomains.Add($cd) | Out-Null
}

# 预编译正则表达式以提升性能 (RFC标准域名格式)
$domainRegex = '^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$'

foreach ($url in $urlList) {
    Write-Log "正在拉取并解析: $url"
    try {
        # 使用 Invoke-RestMethod 替代废弃的 WebClient，提升现代环境下的请求效率
        $content = Invoke-RestMethod -Uri $url -Headers @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        $lines = $content -split "`n"

        foreach ($line in $lines) {
            $line = $line.Trim()

            # 快速跳过空行和各类注释行
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("!") -or $line.StartsWith("#") -or $line.StartsWith("[")) {
                continue
            }

            $domain = $null
            $isWhitelist = $line.StartsWith("@@")

            if ($isWhitelist) {
                $line = $line.Substring(2)
            }

            # 使用 switch -Regex 替代 if-elseif 链，大幅优化正则匹配性能
            switch -Regex ($line) {
                '^\|\|([a-zA-Z0-9.-]+)(?:\^.*)?$' { 
                    # 匹配 Adblock/Easylist 格式，并兼容末尾带有修饰符的情况 (如 ^$third-party)
                    $domain = $Matches[1]
                    break 
                }
                '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+)' { 
                    # 匹配 Hosts 格式
                    $domain = $Matches[1]
                    break 
                }
                '^(?:address|server)=/([a-zA-Z0-9.-]+)/' { 
                    # 匹配 Dnsmasq 格式
                    $domain = $Matches[1]
                    break 
                }
                '^DOMAIN(?:-SUFFIX)?,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' { 
                    # 匹配 Surge/Clash 格式
                    $domain = $Matches[1]
                    break 
                }
                '^([a-zA-Z0-9.-]+)$' { 
                    # 匹配纯域名格式
                    $domain = $Matches[1]
                    break 
                }
            }

            # 验证域名合法性并加入对应集合
            if ($domain -and $domain -match $domainRegex) {
                if ($isWhitelist) {
                    $excludedDomains.Add($domain) | Out-Null
                } else {
                    $uniqueRules.Add($domain) | Out-Null
                }
            }
        }
    }
    catch {
        Write-Log "处理 $url 时出错: $_"
    }
}

Write-Log "规则拉取完成。候选黑名单: $($uniqueRules.Count) 个，白名单: $($excludedDomains.Count) 个。"
Write-Log "正在使用无分配算法排查顶级域名白名单与冗余黑名单 (极速模式)..."

# 过滤白名单并清理冗余子域名
$optimizedRules = [System.Collections.Generic.List[string]]::new()

foreach ($domain in $uniqueRules) {
    $isWhitelisted = $false
    
    # 步骤一：处理「放行和排查被豁免的父级域名」
    if ($excludedDomains.Contains($domain)) {
        continue
    }

    $dotIndex = $domain.IndexOf('.')
    # 利用 IndexOf 游走字符串层级，避免使用 -split 造成海量内存分配
    while ($dotIndex -ge 0 -and $dotIndex -lt ($domain.Length - 1)) {
        $parentDomain = $domain.Substring($dotIndex + 1)
        if ($excludedDomains.Contains($parentDomain)) {
            $isWhitelisted = $true
            break
        }
        $dotIndex = $domain.IndexOf('.', $dotIndex + 1)
    }
    
    if ($isWhitelisted) {
        continue
    }

    $isRedundant = $false
    # 步骤二：检查同门上级是否有更大的网覆盖将其设为黑名单冗余
    $dotIndex = $domain.IndexOf('.')
    while ($dotIndex -ge 0 -and $dotIndex -lt ($domain.Length - 1)) {
        $parentDomain = $domain.Substring($dotIndex + 1)
        if ($uniqueRules.Contains($parentDomain)) {
            $isRedundant = $true
            break
        }
        $dotIndex = $domain.IndexOf('.', $dotIndex + 1)
    }

    # 只有未能匹配所有白名单项并且不隶属某高级父级的废余，即为真切要拦截的首批有效规则
    if (-not $isRedundant) {
        $optimizedRules.Add($domain)
    }
}

# 对最终规则进行排序并格式化为 Clash payload 格式
$formattedRules = $optimizedRules | Sort-Object | ForEach-Object { "- '+.$_'" }

$ruleCount = $optimizedRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 创建 YAML 内容
$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime (UTC+8)
# Generated AdBlock rules
# Total entries: $ruleCount

payload:
$($formattedRules -join "`n")
"@

# 定义输出文件路径并写入
$outputPath = "$PSScriptRoot/adblock_reject.yaml"

# 强制使用无 BOM 的 UTF-8 编码，防止部分严苛的 YAML 解析器/内核报错崩溃
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outputPath, $textContent, $utf8NoBom)

Write-Log "优化及筛选处理圆满结束！抛弃冗余节点后最终量级总数: $ruleCount 个"
Write-Log "最终无BOM规则已存储至 : $outputPath"
