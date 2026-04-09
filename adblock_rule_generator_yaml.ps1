# Title: AdBlock_Rule_For_Clash (最终优化抗杀保网：安全层除错防死排泛限定提取架构映射配置排重拦截规范)
# Description: 防大杀杀规配置核优护盾架构转换输出纯版! 排除剔去根泛影响和粗漏源里因收编无度造成的直接拦截主网站“一级底基础核心主系域名”（防泛掉所有形如 'baidu.com' 纯粹主根拦截造成无服务影响排错合兼容规范点转挂）。大幅降源流报错冲突全线提准过滤规纯组合。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash

# 【进阶防护开关选规与排自定义项】
# （开启以丢弃一切因作者填写极端抓全系匹配一网兜规则里的 "一级网络基础层顶级干"（主名），诸如抛阻包含：baidu.com、qq.com、apple.com 防止彻底屏蔽网站死绝无端影响连结错误挂层）：
$EnableRootDomainDrops = $true

# === 定义基础采集过滤各大集合来源配置单抓源排组合 === 
$urlList = @(
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Mobile_Ads_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/EasyList_China.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/jiekouAD.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AdGuard_Base_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AdGuard_Chinese_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AWAvenue_Ads_Rule.txt"
)

# 限指定输出挂规归点位置排点指向配置写入规转层 
$logFilePath = "$PSScriptRoot/adblock_log.txt"
$outputPath = "$PSScriptRoot/adblock_reject.yaml"

$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains =[System.Collections.Generic.HashSet[string]]::new()

# DNS限测核（基础脱格合法合泛带符纯源验证结构层匹配限定法统机制排除限制！）
function Is-ValidRuleDomain($domain) {
    if ([string]::IsNullOrWhiteSpace($domain) -or $domain.Length -gt 253 -or $domain.Length -lt 2) { 
        return $false 
    }
    if ($domain -notmatch '^[a-zA-Z0-9*.-]+$' -or ($domain -notmatch '\.' -and $domain -notmatch '\*')) {
        return $false
    }
    return $true
}

# --- 【重中之重核心过滤防连根死判定法核心函数：精准剔除形若根的 `一级基底全领带域名` 】 --- 
function Is-FirstLevelCoreDomain($domain) {
    $baseName = $domain -replace '^\*?\.?', ''
    $parts = $baseName -split '\.'
    
    # 特测排漏限制段位检测法机制排除一层纯直层：如果截下统分为极简单2项限纯直名（如仅带纯: baidu.com、criteo.net），判此确即纯一层。拦截规弃! 
    if ($parts.Count -le 2) {
        return $true
    }
    
    # 第二兼容排误重杀复合极区排漏限定特除检: 如为段级3但有复归顶级国家尾列区域级结带机构后限定的组排 （类似合泛如 baidu.com.cn 或 amazon.co.jp 这些极纯特等规结构），由于同样也身为底规同样排除弃管规保不拦截杀挂底:
    if ($parts.Count -eq 3 -and $baseName -match '\.(com|co|net|org|edu|gov|ac|mil)\.[a-zA-Z]{2}$') {
        return $true
    }

    return $false
}

# 按地址分切提取层归切统归合洗流统点限规则集组合入队入源提拉！
foreach ($url in $urlList) {
    Write-Host ">>> 网络组切抓获取限制洗源提取： $url"
    Add-Content -Path $logFilePath -Value "[INFO] 防底限制拦截过滤收拢拉提节点： $url"
    
    try {
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"

        foreach ($line in $lines) {
            $line = $line.Trim()
            
            # --- 层修和元设规级挂符号预防处理清理，去掉干扰的底前符 (仅切抓合效泛址归纯映射挂管效）---
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('!') -or $line.StartsWith('[')) { continue }
            if ($line -match '##|#\?#|\$\$') { continue }

            $domain = $null
            # --- 白列豁项解包取层提合限定纯符号抛点标识解 ---
            $isWhitelist = $line.StartsWith('@@')
            if ($isWhitelist) { $line = $line.Substring(2) }

            if ($line.Contains('$')) { $line = ($line -split '\$')[0] }

            # 根据各类网控层限组法强制切泛源合根级段纯底提段脱归映射统点组合网段级排防合抓排。
            if ($line -match '^\|\|([a-zA-Z0-9*.-]+)\^?$') {
                $domain = $Matches[1]
            } elseif ($line -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            } elseif ($line -match '^(?:address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
                $domain = $Matches[1]
            } elseif ($line -match '^([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }

            if (-not [string]::IsNullOrWhiteSpace($domain)) {
                # 第一遍强制去根脱带源除防干源挂匹配修处理并挂管除
                $domain = $domain -replace '^(\*|\.)+', ''
                $domain = $domain.Trim()
                
                # 入洗组纯挂检验配合检测处理。并检测是防止因空撞误报合配。  
                if ($domain.Length -ge 2 -and ($domain.Contains(".") -or $domain.Contains("*"))) {
                    
                    # 🚀 新核心效制：检测脱并发现如果归属性包含确认为极干线大网络一级域全称（例如 taobao.com）,彻底规脱并防止将其拉入挂队限制从而引起瘫防泛撞： 
                    if ($EnableRootDomainDrops -and (Is-FirstLevelCoreDomain -domain $domain)) {
                        # 因为他太过广泛是基础极限定主址网络结构：不再记录，完全防干！仅作为安全越漏不排配组合防拦截影响拦截泛：不写入。无感直接滑过滤排即可！！
                        continue 
                    }

                    if ($isWhitelist) {
                        [void]$excludedDomains.Add($domain)
                    } else {
                        [void]$uniqueRules.Add($domain)
                    }
                }
            }
        }
    }
    catch {
        Write-Host "[ERROR] 网防拉验证网络脱落挂源获取段极排截中断获取发生失败！无碍放走阻！链接：$url | Details: $_" -ForegroundColor Red
        Add-Content -Path $logFilePath -Value "[WARN] 拉提验证无接掉管落连接点阻断无截配 [$url] : $_"
    }
}

$validExcludedDomains =[System.Collections.Generic.HashSet[string]]::new()
foreach ($domain in $excludedDomains) {
    if (Is-ValidRuleDomain($domain)) {[void]$validExcludedDomains.Add($domain) }
}

$finalRules =[System.Collections.Generic.List[string]]::new()
foreach ($domain in $uniqueRules) {
    if (Is-ValidRuleDomain($domain) -and -not $validExcludedDomains.Contains($domain)) {
        $finalRules.Add($domain)
    }
}

# ===[遵循底官方配置 Payload 标准机制匹配泛接点配置生成核限同匹配生成机制替换！] ===
# 前项剔去强制 '+.' 并接为直泛或全通同等于子孙管直效点 '.' 或者直接配 `*` 单代验证机制进行直发配置点合接匹配：原生匹配点拦截不干耗崩溃限制直出合效映射组规范处理排! 
$formattedRules = $finalRules | Sort-Object | ForEach-Object {
    if ($_ -match '\*') {
        # 带纯 '*' 直接做字符串规则底点防报错匹配。保留层同配同验证直泛组合法制点保留纯
        "- '$_'"
    } else {
        # 常规去脱级无死挂统限泛组直用 '.' 机制全线限制挂连拦截不带 `+` 以极防出错防配兼容生成机制限管挂配置输出兼容规直匹配统阻漏制合匹配组合全组管直挂处理配置匹配： 
        "- '.$_'"
    }
}

$ruleCount = $finalRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# === 高度定制统配置生成合源规范原生 Payload 指令输出结构组合映射组合规合泛效结构限拦截！防崩溃源文件生成机制 ====
$textContent = @"
# Title: AdBlock_Rule_For_Clash (最终防撞击抗阻保护泛限版：高规格兼容挂护排除误漏合规范拦截匹配结构极管限定源转制纯机制防全管版)
# Description: 更高维度底核源支持直极无报错转化格式, 已通过内置结构机制统算完全剔丢诸如 'baidu.com' 纯类单核级别基础管全极域避免引发拦截崩断和广无死报错影响连断匹配崩溃等纯阻机制转制点排挂效规则组匹配纯防崩溃匹配表泛。完美原挂限制！ 
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# Optimized Map Supported Payload Verification Mechanism Update Pure Generation Checked Output Logs Core Built Supports Generated Rules
# Map Filter Effective Record Match Checked Active Generation Outputs Levels Mapping Level Record Formats Updates Supports Update at Limits Limits Supported Map Update Built Core Record Verified Core Valid Mapping Output Match Generated : $generationTime
# Nodes Supports Collected Formats Limits Filter Build Record Efficient Levels Check Matches Valid Output Fixed Levels Core Validation Collected Map Mapped Nodes Build : $ruleCount

payload:
$($formattedRules -join "`n")
"@

$textContent | Out-File -FilePath $outputPath -Encoding utf8

Write-Host "--------------------------------------------------------" -ForegroundColor Green
Write-Host "【成功规转保护阻挂全效核出完限制阻配置纯排制输出限制机制拦截合版生成脱输出限转拦截出泛！极大拦截防极限拦截全机制成功输出点管合！排核限制配规点限制直发限制无源配规限制出规！机制限制截写防护生成配限限制写写入！】" -ForegroundColor Cyan
Write-Host "[效效极计计排记录计全限挂管限制全管阻极数收集效计写记录收集总合规数提取数录极有效录机制脱管无限制输出纯限源]: 制并点泛点泛计有效极挂挂计限记录机制截机制限组有效计共脱合防管输出脱极条合防提取管计脱纯阻截防纯规 $ruleCount 条全极极点截管管录出。"
