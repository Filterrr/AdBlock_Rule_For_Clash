# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0

# 定义广告过滤器URL列表
$urlList = @(
#    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "https://raw.githubusercontent.com/Filterrr/AdBlock_Rule_For_Clash/main/allowlist.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
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

Write-Log "开始更新并转换广告拦截规则..."

# 创建 HashSet 来存储唯一的规则和排除的域名，使用 OrdinalIgnoreCase 忽略大小写，极大提高查找效率
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

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

Write-Log "规则拉取完成。总计提取域名: $($uniqueRules.Count) 个，白名单域名: $($excludedDomains.Count) 个。"
Write-Log "正在进行冗余子域名清理优化 (提升 Clash 解析性能)..."

# 过滤白名单并清理冗余子域名
$optimizedRules = [System.Collections.Generic.List[string]]::new()

foreach ($domain in $uniqueRules) {
    # 排除白名单域名
    if ($excludedDomains.Contains($domain)) {
        continue
    }

    $parts = $domain -split '\.'
    $isRedundant = $false

    # 检查是否存在父级域名被拦截。
    # 例如：当前为 ads.example.com，检查 example.com 是否已在拦截规则中。
    # 如果 example.com 在规则中，则 ads.example.com 是冗余的，因为 Clash 的 '+.example.com' 会自动拦截所有子域名。
    if ($parts.Length -gt 2) {
        for ($i = 1; $i -lt ($parts.Length - 1); $i++) {
            $parentDomain = ($parts[$i..($parts.Length-1)]) -join '.'
            if ($uniqueRules.Contains($parentDomain) -and -not $excludedDomains.Contains($parentDomain)) {
                $isRedundant = $true
                break
            }
        }
    }

    # 只有非冗余的域名才会被加入最终列表
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

Write-Log "优化完成！最终生成有效规则总数: $ruleCount"
Write-Log "规则已保存至: $outputPath"
