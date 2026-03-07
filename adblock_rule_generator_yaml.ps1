# Title: AdBlock_Rule_For_Clash (Optimized)
# Description: 适用于Clash的域名拦截规则集，包含深度去重与子域名归并逻辑
# Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

# --- 配置区 ---
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
$outputPath = "$PSScriptRoot/adblock_reject.yaml"

# 使用不区分大小写的 HashSet 确保基础去重
$rawRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$rawExcludes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# --- 工具函数 ---

# DNS 规范验证
function Is-ValidDNSDomain($domain) {
    if ([string]::IsNullOrWhiteSpace($domain) -or $domain.Length -gt 253) { return $false }
    $labels = $domain -split "\."
    if ($labels.Count -lt 2) { return $false }
    foreach ($label in $labels) {
        if ($label.Length -eq 0 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$") { return $false }
    }
    return $labels[-1] -notmatch "^\d+$" # TLD 不能全是数字
}

# 深度去重：如果父域名已存在，则剔除子域名
function Optimize-DomainList($domains) {
    Write-Host "正在进行深度归并去重..." -ForegroundColor Cyan
    # 按长度排序，确保父域名先被处理
    $sorted = $domains | Sort-Object { $_.Length }, $_
    $optimized = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($d in $sorted) {
        $isRedundant = $false
        $parts = $d.Split('.')
        # 逐层检查父域
        for ($i = 1; $i -lt $parts.Count; $i++) {
            $parent = ($parts[$i..($parts.Count-1)]) -join '.'
            if ($optimized.Contains($parent)) {
                $isRedundant = $true
                break
            }
        }
        if (-not $isRedundant) { $optimized.Add($d) | Out-Null }
    }
    return $optimized
}

# --- 主逻辑 ---

$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36")

foreach ($url in $urlList) {
    Write-Host "正在下载: $url"
    try {
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"
        foreach ($line in $lines) {
            $line = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('!')) { continue }

            # 处理白名单 @@
            if ($line.StartsWith('@@')) {
                if ($line -match '\|\|([a-zA-Z0-9.-]+)\^') {
                    $rawExcludes.Add($Matches[1]) | Out-Null
                }
            }
            # 处理 ||domain^ 格式
            elseif ($line -match '^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$') {
                $rawRules.Add($Matches[1]) | Out-Null
            }
            # 处理 Hosts 格式 (0.0.0.0 domain)
            elseif ($line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                $rawRules.Add($Matches[2]) | Out-Null
            }
            # 处理 Dnsmasq 格式 (address=/domain/)
            elseif ($line -match '^(address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
                $rawRules.Add($Matches[2]) | Out-Null
            }
            # 处理纯域名格式
            elseif ($line -match '^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                $rawRules.Add($Matches[1]) | Out-Null
            }
        }
    } catch {
        Write-Host "跳过错误 URL: $url" -ForegroundColor Yellow
    }
}

# 1. 验证并清理拦截规则
$validRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($r in $rawRules) {
    if (Is-ValidDNSDomain($r)) { $validRules.Add($r.ToLower()) | Out-Null }
}

# 2. 执行深度去重（子域名归并）
$deepRules = Optimize-DomainList($validRules)

# 3. 验证并清理白名单
$validExcludes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($e in $rawExcludes) {
    if (Is-ValidDNSDomain($e)) { $validExcludes.Add($e.ToLower()) | Out-Null }
}

# 4. 最终过滤：剔除在白名单中的条目（包含父域检查）
$finalRules = New-Object System.Collections.Generic.List[string]
foreach ($rule in $deepRules) {
    $isWhite = $false
    $parts = $rule.Split('.')
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        $check = ($parts[$i..($parts.Count-1)]) -join '.'
        if ($validExcludes.Contains($check)) {
            $isWhite = $true
            break
        }
    }
    if (-not $isWhite) { $finalRules.Add($rule) }
}

# 5. 排序并生成 YAML
$finalRules.Sort()
$formattedRules = $finalRules | ForEach-Object { "  - '$_'" }
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Generated on: $generationTime (UTC+8)
# Total entries: $($finalRules.Count)
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash

payload:
$($formattedRules -join "`n")
"@

$textContent | Out-File -FilePath $outputPath -Encoding utf8
Write-Host "处理完成！生成规则数: $($finalRules.Count)" -ForegroundColor Green
