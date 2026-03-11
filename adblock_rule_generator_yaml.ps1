# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0

# 定义广告过滤器URL列表
$urlList = @(
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",  
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"
)

# 日志文件路径
$logFilePath = "$PSScriptRoot/adblock_log.txt"

# [优化] 使用 OrdinalIgnoreCase 忽略域名大小写，避免大小写导致的重复统计
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# DNS规范验证函数 (保持不变)
function Is-ValidDNSDomain($domain) {
    if ($domain.Length -gt 253) { return $false }
    $labels = $domain -split "\."
    foreach ($label in $labels) {
        if ($label.Length -eq 0 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$") { return $false }
    }
    $tld = $labels[-1]
    if ($tld -notmatch "^[a-zA-Z]{2,}$") { return $false }
    return $true
}

# [优化] 定义请求头（用于 Invoke-RestMethod）
$headers = @{
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

foreach ($url in $urlList) {
    Write-Host "正在处理: $url"
    Add-Content -Path $logFilePath -Value "正在处理: $url"
    try {
        # [优化] 使用更现代的 Invoke-RestMethod 替代废弃的 WebClient
        $content = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
        $lines = $content -split "`n"

        # [优化] 使用 switch -Regex 替代冗长的 if-elseif 链，极大提升正则匹配速度
        switch -Regex ($lines) {
            '^@@' {
                $domains = $_ -replace '^@@', '' -split '[^\w.-]+'
                foreach ($domain in $domains) {
                    if (-not [string]::IsNullOrWhiteSpace($domain) -and $domain -match '[\w-]+(\.[\w-]+)+') {
                        $excludedDomains.Add($domain.Trim()) | Out-Null
                    }
                }
            }
            '^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$' { 
                $uniqueRules.Add($Matches[1]) | Out-Null 
            }
            # [优化] 合并 IPv4 和 IPv6 规则的正则表达式
            '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$' { 
                $uniqueRules.Add($Matches[1]) | Out-Null 
            }
            # [优化] 合并 dnsmasq 的 address 和 server 规则
            '^(?:address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$' { 
                $uniqueRules.Add($Matches[1]) | Out-Null 
            }
            '^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$' { 
                $uniqueRules.Add($Matches[1]) | Out-Null 
            }
        }
    }
    catch {
        Write-Host "处理 $url 时出错: $_"
        Add-Content -Path $logFilePath -Value "处理 $url 时出错: $_"
    }
}

# 写入文件之前的DNS规范验证
$validRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$validExcludedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($domain in $uniqueRules) {
    if (Is-ValidDNSDomain($domain)) { $validRules.Add($domain) | Out-Null }
}
foreach ($domain in $excludedDomains) {
    if (Is-ValidDNSDomain($domain)) { $validExcludedDomains.Add($domain) | Out-Null }
}

# [核心优化] 使用 HashSet 原生的 ExceptWith 方法直接在内存中剔除白名单，替代缓慢的 Where-Object 管道
$validRules.ExceptWith($validExcludedDomains)

# 对规则进行排序并格式化
$formattedRules = [string[]]$validRules | Sort-Object | ForEach-Object {"- '+.$_'"}

# 统计生成的规则条目数量
$ruleCount = $validRules.Count

# 获取当前时间并转换为东八区时间
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 创建文本格式的字符串
$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime
# Generated AdBlock rules
# Total entries: $ruleCount

payload:
$($formattedRules -join "`n")
"@

# 定义输出文件路径
$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$textContent | Out-File -FilePath $outputPath -Encoding utf8

# 输出生成的有效规则总数
Write-Host "生成的有效规则总数: $ruleCount"
Add-Content -Path $logFilePath -Value "Total entries: $ruleCount"
