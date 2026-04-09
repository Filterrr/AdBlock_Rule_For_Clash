# Title: AdBlock_Rule_For_Clash (最终优化抗杀保网版)
# Description: 自动采集、去重、防误杀（排除一级主域名）的 Clash 规则生成器

$EnableRootDomainDrops = $true

# === 配置采集源 ===
$urlList = @(
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt"
)

$logFilePath = "$PSScriptRoot/adblock_log.txt"
$outputPath = "$PSScriptRoot/adblock_reject.yaml"

$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new()

# --- 核心判定：是否为一级主域名 ---
function Is-FirstLevelCoreDomain($domain) {
    # 移除通配符
    $d = $domain -replace '^\*?\.?', ''
    # 匹配模式：非复合后缀的二级域名 (如 baidu.com) 或 复合后缀的二级域名 (如 baidu.com.cn)
    # 逻辑：如果域名分段 <= 2，或者分段为3且后缀为常见复合类型，则判定为一级域名
    $parts = $d -split '\.'
    if ($parts.Count -le 2) { return $true }
    if ($parts.Count -eq 3 -and $d -match '\.(com|co|net|org|edu|gov|ac|mil)\.(cn|jp|hk|uk|tw|au)$') { return $true }
    return $false
}

# --- 抓取与处理 ---
foreach ($url in $urlList) {
    Write-Host ">>> 正在处理: $url"
    try {
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"
        foreach ($line in $lines) {
            $line = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('!') -or $line.StartsWith('[')) { continue }
            
            # 处理白名单 @@
            $isWhitelist = $line.StartsWith('@@')
            if ($isWhitelist) { $line = $line.Substring(2) }
            if ($line.Contains('$')) { $line = ($line -split '\$')[0] }

            # 提取域名
            $domain = $null
            if ($line -match '^\|\|([a-zA-Z0-9*.-]+)\^?$') { $domain = $Matches[1] }
            elseif ($line -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') { $domain = $Matches[1] }
            elseif ($line -match '^([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})$') { $domain = $Matches[1] }

            if ($domain) {
                $domain = ($domain -replace '^\*?\.?', '').Trim().ToLower()
                
                # 核心过滤：如果判定为一级域名且开启了保护，则直接跳过
                if ($EnableRootDomainDrops -and (Is-FirstLevelCoreDomain $domain)) { continue }

                if ($isWhitelist) { [void]$excludedDomains.Add($domain) }
                else { [void]$uniqueRules.Add($domain) }
            }
        }
    } catch { Write-Host "[ERROR] 获取失败: $url" -ForegroundColor Red }
}

# --- 过滤白名单并生成最终格式 ---
$finalRules = [System.Collections.Generic.List[string]]::new()
foreach ($d in $uniqueRules) {
    if (-not $excludedDomains.Contains($d)) {
        if ($d -match '\*') { $finalRules.Add("- '$d'") }
        else { $finalRules.Add("- '＋.$d'") }
    }
}

# --- 输出文件 ---
$generationTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ruleCount = $finalRules.Count

$header = @"
# Title: AdBlock_Rule_For_Clash
# Generated: $generationTime
# Total Rules: $ruleCount
# Info: 已剔除一级主域名，保护基础连通性。
payload:
"@

$header | Out-File -FilePath $outputPath -Encoding utf8
$finalRules | Sort-Object | Out-File -FilePath $outputPath -Append -Encoding utf8

Write-Host "--------------------------------------------------------" -ForegroundColor Green
Write-Host "处理完成！成功生成 $ruleCount 条规则，已存至: $outputPath" -ForegroundColor Cyan
