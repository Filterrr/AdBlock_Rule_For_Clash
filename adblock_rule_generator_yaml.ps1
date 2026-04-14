# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0

# === 自定义需要强制放行拦截的白名单域名 ===
# 支持在此手动硬编码一些需直接排除自身以及全体下级子域的域名（相当于白名单特权池）。如 "example.com"
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
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt"
)

# 日志文件路径
$logFilePath = "$PSScriptRoot/adblock_log.txt"
Clear-Content -Path $logFilePath -ErrorAction SilentlyContinue

# 日志输出函数
function Write-Log($message) {
    Write-Host $message
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
}

Write-Log "开始更新并转换广告拦截规则..."

# 创建 HashSet 来存储唯一的规则和排除的域名，使用 OrdinalIgnoreCase 忽略大小写，极大提高查找效率
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# 录入手动定义的预设全局强制白名单 (及其父域名逻辑保护)
foreach ($cd in $customExcludedDomains) {
    $excludedDomains.Add($cd) | Out-Null
}

# 创建 WebClient 对象用于下载规则
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
$webClient.Encoding = [System.Text.Encoding]::UTF8

# 预编译正则表达式以提升性能
# 匹配标准域名的正则 (符合 RFC 规范)
$domainRegex = '^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$'

foreach ($url in $urlList) {
    Write-Log "正在拉取并处理: $url"
    try {
        $content = $webClient.DownloadString($url)
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

            # 1. 匹配 Adblock/Easylist 格式 (例如: ||example.com^ 或 ||example.com^$third-party)
            if ($line -match '^\|\|([a-zA-Z0-9.-]+)(?:\^|$)') {
                $domain = $Matches[1]
            }
            # 2. 匹配 Hosts 格式 (例如: 0.0.0.0 example.com 或 127.0.0.1 example.com 或 ::1 example.com)
            elseif ($line -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+)') {
                $domain = $Matches[1]
            }
            # 3. 匹配 Dnsmasq 格式 (例如: address=/example.com/ 或 server=/example.com/)
            elseif ($line -match '^(?:address|server)=/([a-zA-Z0-9.-]+)/') {
                $domain = $Matches[1]
            }
            # 4. 匹配纯域名格式
            elseif ($line -match '^([a-zA-Z0-9.-]+)$') {
                $domain = $Matches[1]
            }
            # 5. Surge/Clash规则: DOMAIN-SUFFIX,example.com
            elseif ($line -match '^DOMAIN(?:-SUFFIX)?,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})') {
                $domain = $Matches[1]
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

Write-Log "规则拉取完成。总计提取提取候选黑名单: $($uniqueRules.Count) 个，显性白名单(需放行): $($excludedDomains.Count) 个。"
Write-Log "正在排查和继承顶级域名白名单 以及 进行冗余黑名单子域优化清理 (极速模式)..."

# 过滤白名单并清理冗余子域名
$optimizedRules = [System.Collections.Generic.List[string]]::new()

foreach ($domain in $uniqueRules) {
    $parts = $domain -split '\.'
    $isWhitelisted = $false
    
    # 步骤一：处理「放行和排查被豁免的父级域名」，解决“放行example.com则对应放弃屏蔽所有下属多级域名”的需求。
    # 递归查证是否本身，或者是其更高层次的域(如 .com 之前的截段)已被登记为受信任在 $excludedDomains 池子里
    for ($i = 0; $i -lt ($parts.Length - 1); $i++) {
        # $i=0 是查证本域名完全匹配，之后截短前一级向父层搜寻匹配(仅对二级以上的深级生效)
        $checkDomain = ($parts[$i..($parts.Length-1)]) -join '.'
        if ($excludedDomains.Contains($checkDomain)) {
            $isWhitelisted = $true
            break
        }
    }
    
    # 该对象或者是对象的顶级存在已获得放行特许
    if ($isWhitelisted) {
        continue
    }

    $isRedundant = $false
    # 步骤二：由于已确认无需进行白名单放行，下面只要向上去检查同门上级是否有更大的网覆盖将其设为黑名单冗余。
    # 检查当前对象的较高层次结构是否存在父级域名早已被囊入黑拦截数组，被囊入的话在 Clash 端相当于使用 $+.$parentDomain 被涵盖拦截了，故在此做“下下级剪枝抛弃计算”，提升最终yaml生效性能。
    if ($parts.Length -gt 2) {
        for ($i = 1; $i -lt ($parts.Length - 1); $i++) {
            $parentDomain = ($parts[$i..($parts.Length-1)]) -join '.'
            if ($uniqueRules.Contains($parentDomain)) {
                $isRedundant = $true
                break
            }
        }
    }

    # 只有未能匹配所有白名单项并且不隶属某高级父级的废余，即为真切要拦截的首批有效规则条列加入清单库中。
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
$textContent | Out-File -FilePath $outputPath -Encoding utf8

Write-Log "优化及筛选处理圆满结束！在抛弃被保护及各等长黑单父节点覆写冗余以后生成无用消耗节点减少为最终量级总数: $ruleCount 个"
Write-Log "最终规则成功序列存储已落款保存至工作表区至 : $outputPath 完整目录待更新配置"
