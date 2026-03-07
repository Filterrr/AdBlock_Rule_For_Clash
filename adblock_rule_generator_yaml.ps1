# ==========================================
# Adblock Rule Generator (Optimized Version)
# ==========================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host "--------------------------------------"
Write-Host " Adblock Rule Generator (Optimized)"
Write-Host "--------------------------------------"

# 输出文件
$outputFile = "adblock_reject.yaml"

# 规则源
$ruleSources = @(
# "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt",
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

# 白名单
$excludeDomains = @(
"localhost",
"local",
"example.com"
)

# ----------------------------
# 初始化数据结构
# ----------------------------

$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$validRules  = [System.Collections.Generic.HashSet[string]]::new()
$excludedSet = [System.Collections.Generic.HashSet[string]]::new()

foreach ($d in $excludeDomains) {
    $excludedSet.Add($d) | Out-Null
}

# ----------------------------
# 域名合法性判断
# ----------------------------

function Test-Domain {

    param ($domain)

    if ([string]::IsNullOrWhiteSpace($domain)) {
        return $false
    }

    if ($domain.Length -gt 253) {
        return $false
    }

    if ($domain -notmatch "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") {
        return $false
    }

    return $true
}

# ----------------------------
# 下载并解析规则
# ----------------------------

$totalLines = 0

foreach ($url in $ruleSources) {

    Write-Host "Downloading: $url"

    try {

        $content = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 60
        $lines = $content.Content -split "`n"

        foreach ($line in $lines) {

            $totalLines++

            $domain = $line.Trim()

            if ($domain.StartsWith("!")) { continue }
            if ($domain.StartsWith("#")) { continue }
            if ($domain.StartsWith("||")) { $domain = $domain.Substring(2) }
            if ($domain.Contains("^")) { $domain = $domain.Split("^")[0] }

            $domain = $domain.ToLower()
            $domain = $domain -replace '^www\.',''

            if (Test-Domain $domain) {

                if (-not $excludedSet.Contains($domain)) {

                    $uniqueRules.Add($domain) | Out-Null

                }

            }

        }

    }
    catch {

        Write-Host "Download failed: $url"

    }

}

Write-Host "Total raw lines: $totalLines"
Write-Host "Unique domains: $($uniqueRules.Count)"

# ----------------------------
# 父域去重
# ----------------------------

Write-Host "Running root-domain dedup..."

$rootDedup = [System.Collections.Generic.HashSet[string]]::new()

$sorted = $uniqueRules | Sort-Object

foreach ($domain in $sorted) {

    $parts = $domain.Split('.')

    $skip = $false

    for ($i = 1; $i -lt $parts.Length - 1; $i++) {

        $parent = ($parts[$i..($parts.Length-1)] -join '.')

        if ($rootDedup.Contains($parent)) {

            $skip = $true
            break

        }

    }

    if (-not $skip) {

        $rootDedup.Add($domain) | Out-Null

    }

}

$finalRules = $rootDedup

Write-Host "After root dedup: $($finalRules.Count)"

# ----------------------------
# 生成 YAML
# ----------------------------

Write-Host "Generating YAML..."

$yaml = @()
$yaml += "payload:"

foreach ($domain in ($finalRules | Sort-Object)) {

    $yaml += "  - '+.$domain'"

}

$yaml | Out-File $outputFile -Encoding utf8

Write-Host "--------------------------------------"
Write-Host "Output file: $outputFile"
Write-Host "Total rules: $($finalRules.Count)"
Write-Host "--------------------------------------"



