# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，集成深度去重逻辑
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash

# 定义广告过滤器URL列表
$urlList = @(
    "https://hblock.molinero.dev/hosts_adblock.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",  
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",  
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_10_Useful/filter.txt",  
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",  
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",  
    "https://easylist-downloads.adblockplus.org/easylist.txt",  
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",  
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",  
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",  
    "https://cdn.jsdelivr.net/gh/xinggsf/Adblock-Plus-Rule@master/rule.txt",  
    "https://anti-ad.net/adguard.txt"
)

$logFilePath = "$PSScriptRoot/adblock_log.txt"
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new()

$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

function Is-ValidDNSDomain($domain) {
    if ($domain.Length -gt 253) { return $false }
    $labels = $domain -split "\."
    foreach ($label in $labels) {
        if ($label.Length -eq 0 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$") { return $false }
    }
    if ($labels[-1] -notmatch "^[a-zA-Z]{2,}$") { return $false }
    return $true
}

# 1. 抓取与初步提取
foreach ($url in $urlList) {
    Write-Host "正在处理: $url"
    try {
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"
        foreach ($line in $lines) {
            $line = $line.Trim()
            if ($line.StartsWith('@@')) {
                $domain = $line -replace '^@@\|?\|?', '' -replace '\^.*$', ''
                if ($domain -match '^[a-zA-Z0-9.-]+$') { $excludedDomains.Add($domain) | Out-Null }
            }
            elseif ($line -match '^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$') { $uniqueRules.Add($Matches[1]) | Out-Null }
            elseif ($line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') { $uniqueRules.Add($Matches[2]) | Out-Null }
            elseif ($line -match '^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') { $uniqueRules.Add($Matches[1]) | Out-Null }
        }
    } catch { Write-Host "处理 $url 时出错" }
}

# 2. 基础过滤与验证
$validRules = $uniqueRules | Where-Object { (Is-ValidDNSDomain $_) -and (-not $excludedDomains.Contains($_)) }

# 3. 深度去重功能（父子域名逻辑）
# 先排序，确保父域名排在子域名之前或紧邻
$sortedRules = $validRules | Sort-Object
$finalList = New-Object System.Collections.Generic.List[string]
$lastAdded = ""

foreach ($current in $sortedRules) {
    if ($null -eq $lastAdded -or $lastAdded -eq "") {
        $finalList.Add($current)
        $lastAdded = $current
        continue
    }
    # 如果当前域名是上一个已添加域名的子域名，则跳过
    # 例如：lastAdded="example.com", current="www.example.com"
    if ($current.EndsWith(".$lastAdded")) {
        continue 
    } else {
        $finalList.Add($current)
        $lastAdded = $current
    }
}

# 4. 生成 YAML 文本
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")
$ruleCount = $finalList.Count
$formattedRules = $finalList | ForEach-Object {"  - '$_'"}

$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Generated on: $generationTime
# Total entries after deep deduplication: $ruleCount

payload:
$($formattedRules -join "`n")
"@

$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$textContent | Out-File -FilePath $outputPath -Encoding utf8 -Force
Write-Host "去重完成！最终规则条目: $ruleCount"
