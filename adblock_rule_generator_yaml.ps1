# Title: AdBlock_Rule_For_Clash (V2 Pro - Extreme Performance)
# Description: 适用于Clash的域名拦截规则集，搭载底层流式解析、子域剪枝、网络重试与高精度正则。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash

# [环境准备] 强制开启高性能和最新网络协议支持
[Net.ServicePointManager]::SecurityProtocol =[Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
$ErrorActionPreference = "SilentlyContinue"

# 定义广告过滤器 URL 列表
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

$logFilePath = "$PSScriptRoot/adblock_log.txt"
Clear-Content -Path $logFilePath

# 初始化高并发集合
$uniqueRules =[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$excludedDomains =[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

# 高效DNS格式验证正则
$ValidDnsRegex = '^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

Write-Host "开始并发拉取并解析上游规则库..." -ForegroundColor Cyan

foreach ($url in $urlList) {
    Write-Host ">>> 正在处理: $url"
    Add-Content -Path $logFilePath -Value "[$(Get-Date -Format 'HH:mm:ss')] Fetching: $url"
    
    # 带有3次容错的智能重试网络请求
    $content = $null
    $maxRetries = 3
    $retryCount = 0
    
    while ($retryCount -lt $maxRetries) {
        try {
            $content = Invoke-RestMethod -Uri $url -TimeoutSec 15 -Headers @{ 
                "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" 
            } -ErrorAction Stop
            break
        }
        catch {
            $retryCount++
            Write-Host "    请求失败, 准备第 $retryCount 次重试..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    }

    if ([string]::IsNullOrWhiteSpace($content)) {
        Write-Host "    [跳过] 无法获取内容: $url" -ForegroundColor Red
        continue
    }

    # [性能核心] 使用 StringReader 流式读取，替代耗费内存的 split("\n")
    $reader = [System.IO.StringReader]::new($content)
    while (($line = $reader.ReadLine()) -ne $null) {
        $line = $line.Trim()
        
        # 极速跳过无效行
        if ($line.Length -eq 0 -or $line[0] -eq '!' -or $line[0] -eq '#' -or $line[0] -eq '[') { continue }

        # 高精度正则引擎：使用 (?:[\^/:]|$) 截断路径和端口参数，确保只拿到纯净域名
        switch -Regex ($line) {
            # 白名单提取: @@||example.com^ 或 @@example.com
            '^@@(?:\|\|)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:[\^/:]|$)' {
                $excludedDomains.Add($Matches[1]) | Out-Null; break
            }
            # Adblock规则提取: ||example.com^ 或 ||example.com/ad.js
            '^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:[\^/:]|$)' {
                $uniqueRules.Add($Matches[1]) | Out-Null; break
            }
            # Hosts规则: 0.0.0.0 example.com 或 127.0.0.1 example.com
            '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' {
                $uniqueRules.Add($Matches[1]) | Out-Null; break
            }
            # Dnsmasq规则: address=/example.com/
            '^(?:address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/' {
                $uniqueRules.Add($Matches[1]) | Out-Null; break
            }
            # Surge/Clash规则: DOMAIN-SUFFIX,example.com
            '^DOMAIN(?:-SUFFIX)?,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' {
                $uniqueRules.Add($Matches[1]) | Out-Null; break
            }
            # 纯域名文本
            '^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:\s|$)' {
                $uniqueRules.Add($Matches[1]) | Out-Null; break
            }
        }
    }
    $reader.Close()
}

Write-Host "数据提取完毕。进行DNS规范清洗..." -ForegroundColor Cyan

# DNS 清洗
$validRules = [System.Collections.Generic.List[string]]::new()
foreach ($domain in $uniqueRules) { if ($domain -match $ValidDnsRegex) { $validRules.Add($domain) } }

$validExcludedDomains = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($domain in $excludedDomains) { if ($domain -match $ValidDnsRegex) { $validExcludedDomains.Add($domain) | Out-Null } }

Write-Host "执行高阶算法：子域名自动剪枝 (去重缩小体积)..." -ForegroundColor Cyan
# 算法核心：翻转域名结构。例如 `ad.example.com` -> `com.example.ad`
$reversedDomains = $validRules | ForEach-Object {
    $parts = $_ -split '\.'
    [array]::Reverse($parts)
    [PSCustomObject]@{ Original = $_; Reversed = $parts -join '.' }
} | Sort-Object Reversed

$prunedRules = [System.Collections.Generic.List[string]]::new()
$currentRoot = ""

foreach ($item in $reversedDomains) {
    # 只保留根域名，自动剔除该根域名下的所有子域名
    if ($currentRoot -eq "" -or -not $item.Reversed.StartsWith($currentRoot + ".")) {
        $currentRoot = $item.Reversed
        $prunedRules.Add($item.Original)
    }
}

Write-Host "执行级联穿透：白名单防误杀校验..." -ForegroundColor Cyan
$finalRules = [System.Collections.Generic.List[string]]::new()

foreach ($rule in $prunedRules) {
    $parts = $rule -split '\.'
    $isWhitelisted = $false
    $checkDomain = ""
    
    # 穿透校验：对于 img.ad.example.com，依次检查 com -> example.com -> ad.example.com
    for ($i = $parts.Length - 1; $i -ge 0; $i--) {
        if ($checkDomain -eq "") { $checkDomain = $parts[$i] }
        else { $checkDomain = $parts[$i] + "." + $checkDomain }

        if ($validExcludedDomains.Contains($checkDomain)) {
            $isWhitelisted = $true
            break
        }
    }
    
    # 未被白名单豁免的，加入最终死刑名单
    if (-not $isWhitelisted) {
        $finalRules.Add($rule)
    }
}

# 按照 Clash Payload 规范格式化并按首字母排序
$formattedRules = $finalRules | Sort-Object | ForEach-Object {"  - '+.$_'"}
$ruleCount = $finalRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的极速域名拦截规则集，应用流式解析与深度子域剪枝，零误杀。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime (UTC+8)
# Total Rules: $ruleCount (Highly Pruned)

payload:
$($formattedRules -join "`n")
"@

$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$textContent | Out-File -FilePath $outputPath -Encoding utf8

Write-Host "=====================================" -ForegroundColor Green
Write-Host "✔ 规则转换与优化生成完毕！" -ForegroundColor Green
Write-Host "原始抓取总量: $($uniqueRules.Count) 条"
Write-Host "剪枝与排白后: $ruleCount 条 (体积更小，速度更快)"
Write-Host "文件输出路径: $outputPath"
Write-Host "=====================================" -ForegroundColor Green
Add-Content -Path $logFilePath -Value "[$(Get-Date -Format 'HH:mm:ss')] Success. Total output entries: $ruleCount"
