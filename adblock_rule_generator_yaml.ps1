# Title: AdBlock_Rule_For_Clash (Optimized Version)
# Description: 适用于Clash的高效域名拦截规则集，具备子域名剪枝与强效正则提取，降低误杀并缩小体积
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0

# 强制使用 TLS 1.2+ 以防老旧系统下载失败[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor[Net.SecurityProtocolType]::Tls13

# 定义广告过滤器URL列表
$urlList = @(
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "https://raw.githubusercontent.com/Filterrr/AdBlock_Rule_For_Clash/main/allowlist.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt"
)

# 日志文件路径
$logFilePath = "$PSScriptRoot/adblock_log.txt"

# 使用 HashSet 确保初步去重提速
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains =[System.Collections.Generic.HashSet[string]]::new()

# 高效的DNS格式校验 (过滤包含 * 等非法字符的无效域名)
function Is-ValidDNSDomain($domain) {
    if ([string]::IsNullOrWhiteSpace($domain) -or $domain.Length -gt 253) { return $false }
    return $domain -match '^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
}

Clear-Content -Path $logFilePath -ErrorAction SilentlyContinue

foreach ($url in $urlList) {
    Write-Host "正在处理: $url"
    Add-Content -Path $logFilePath -Value "正在处理: $url"
    try {
        # 使用 Invoke-RestMethod 提升下载效率及兼容性
        $content = Invoke-RestMethod -Uri $url -Headers @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" } -ErrorAction Stop
        $lines = $content -split "`n"

        # 使用 switch -Regex 进行单遍极速正则匹配
        foreach ($line in $lines) {
            $line = $line.Trim()
            
            # 提前跳过空行和纯注释行，提升处理速度
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("!") -or $line.StartsWith("#") -or $line.StartsWith("[")) {
                continue
            }

            # 核心规则提取器（优化修饰符、注释兼容）
            switch -Regex ($line) {
                # 匹配白名单: @@||example.com^ 或 @@example.com
                '^@@(?:\|\|)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' {
                    $excludedDomains.Add($Matches[1]) | Out-Null
                    break
                }
                # 匹配 Adblock 格式: ||example.com^$third-party (无视后面修饰符)
                '^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' {
                    $uniqueRules.Add($Matches[1]) | Out-Null
                    break
                }
                # 匹配 Hosts 格式 (IPv4): 0.0.0.0 example.com # 备注
                '^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' {
                    $uniqueRules.Add($Matches[1]) | Out-Null
                    break
                }
                # 匹配 Hosts 格式 (IPv6): ::1 example.com
                '^::1?\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' {
                    $uniqueRules.Add($Matches[1]) | Out-Null
                    break
                }
                # 匹配 Dnsmasq 格式: address=/example.com/
                '^(?:address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/' {
                    $uniqueRules.Add($Matches[1]) | Out-Null
                    break
                }
                # 匹配 Surge/Clash/Quantumult X 传统格式: DOMAIN-SUFFIX,example.com
                '^DOMAIN(?:-SUFFIX)?,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' {
                    $uniqueRules.Add($Matches[1]) | Out-Null
                    break
                }
                # 匹配纯域名格式: example.com
                '^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$' {
                    $uniqueRules.Add($Matches[1]) | Out-Null
                    break
                }
            }
        }
    }
    catch {
        Write-Host "处理 $url 时出错: $_" -ForegroundColor Red
        Add-Content -Path $logFilePath -Value "处理 $url 时出错: $_"
    }
}

Write-Host "开始规范化并过滤规则..."
$validExcludedDomains = [System.Collections.Generic.HashSet[string]]::new()
foreach ($domain in $excludedDomains) {
    if (Is-ValidDNSDomain($domain)) {
        $validExcludedDomains.Add($domain) | Out-Null
    }
}

$validRules =[System.Collections.Generic.HashSet[string]]::new()
foreach ($domain in $uniqueRules) {
    if (Is-ValidDNSDomain($domain)) {
        $validRules.Add($domain) | Out-Null
    }
}

Write-Host "开始子域名智能剪枝 (优化体积与 Clash 运行效率)..."
# 算法：将域名按层级倒置排序 (com.example.ad)，实现根域名覆盖子域名的自动剔除
$reversedDomains = $validRules | ForEach-Object {
    $parts = $_ -split '\.'
    [array]::Reverse($parts)
    [PSCustomObject]@{
        Original = $_
        Reversed = $parts -join '.'
    }
} | Sort-Object Reversed

$prunedRules =[System.Collections.Generic.List[string]]::new()
$currentRoot = ""

foreach ($item in $reversedDomains) {
    # 如果当前域名不是上一个域名的子域名，则保留（例：com.example 不匹配 com.example.ad 则剔除后者）
    if ($currentRoot -eq "" -or -not $item.Reversed.StartsWith($currentRoot + ".")) {
        $currentRoot = $item.Reversed
        $prunedRules.Add($item.Original)
    }
}

Write-Host "开始应用上游白名单 (级联防误杀)..."
$finalRules = [System.Collections.Generic.List[string]]::new()
foreach ($rule in $prunedRules) {
    $parts = $rule -split '\.'
    $isWhitelisted = $false
    $checkDomain = ""
    # 级联验证：如果规则是 ad.example.com，当 example.com 在白名单时，也会将其放行
    for ($i = $parts.Length - 1; $i -ge 0; $i--) {
        if ($checkDomain -eq "") { $checkDomain = $parts[$i] }
        else { $checkDomain = $parts[$i] + "." + $checkDomain }

        if ($validExcludedDomains.Contains($checkDomain)) {
            $isWhitelisted = $true
            break
        }
    }
    if (-not $isWhitelisted) {
        $finalRules.Add($rule)
    }
}

# 格式化为 Clash Domain-Suffix 规范
$formattedRules = $finalRules | Sort-Object | ForEach-Object {"  - '+.$_'"}

$ruleCount = $finalRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 创建文本格式的字符串
$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime
# Total entries: $ruleCount (Optimized with Subdomain Pruning)

payload:
$($formattedRules -join "`n")
"@

# 定义输出文件路径并写入
$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$textContent | Out-File -FilePath $outputPath -Encoding utf8

# 输出生成的有效规则总数
Write-Host "规则生成完毕！" -ForegroundColor Green
Write-Host "原始抓取域名数: $($uniqueRules.Count)"
Write-Host "去除冗余及白名单后有效规则总数: $ruleCount"
Add-Content -Path $logFilePath -Value "Total entries: $ruleCount"
