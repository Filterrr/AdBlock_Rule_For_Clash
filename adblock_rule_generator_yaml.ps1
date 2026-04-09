# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash Meta的纯粹域名拦截规则集，去杂过滤保证低误杀率
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash

# 定义广告过滤器URL列表
$urlList = @(
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Mobile_Ads_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/EasyList_China.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/jiekouAD.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AdGuard_Base_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AdGuard_Chinese_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AWAvenue_Ads_Rule.txt"
)

# 确保脚本始终在正确当前运行根目录
$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$logFilePath = Join-Path -Path $PSScriptRoot -ChildPath "adblock_log.txt"
$outputPath = Join-Path -Path $PSScriptRoot -ChildPath "adblock_reject.yaml"

# HashSet: 使用 OrdinalIgnoreCase 加快匹配及实现排重的最佳方式（不区分大小写）
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# 配置下载工具属性（加上强指定Utf-8解码规则读取原始广告源以防特殊汉字混进配置里导致崩溃）
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ClashMetaBuilder")
$webClient.Encoding = [System.Text.Encoding]::UTF8

# DNS 规则严格合法性检查
function Is-ValidDNSDomain($domain) {
    if ([string]::IsNullOrWhiteSpace($domain) -or $domain.Length -gt 253) { return $false }
    $labels = $domain -split "\."
    if ($labels.Count -lt 2) { return $false } # 最少也该有一个"."结尾的主域名 
    foreach ($label in $labels) {
        if ($label.Length -eq 0 -or $label.Length -gt 63) { return $false }
        # 允许常规的DNS字母连贯规范
        if ($label -notmatch "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$") { return $false }
    }
    $tld = $labels[-1]
    if ($tld -notmatch "^[a-zA-Z]{2,}$") { return $false }
    return $true
}

Clear-Content -Path $logFilePath -ErrorAction SilentlyContinue

foreach ($url in $urlList) {
    Write-Host "正在处理拉取并精简化：$url" -ForegroundColor Cyan
    Add-Content -Path $logFilePath -Value "处理开始：$url"
    
    try {
        $content = $webClient.DownloadString($url)
        # 用通用兼容 \r?\n 回车兼容方式来Split并过滤空行
        $lines = $content -split "`r?`n" 
        
        foreach ($line in $lines) {
            $line = $line.Trim()
            
            #[步骤1: 跳过纯属UI网页调整内容（## 或 #@#），过滤无意义的空行或非规内容和直接正则式等 ]
            if ($line.Length -eq 0 -or 
                $line.StartsWith('!') -or 
                $line.StartsWith('[') -or 
                $line.Contains('##') -or 
                $line.Contains('#@#')) { continue }
            
            # [步骤2: 处理 @@ 白名单规则 ]
            $isWhitelist = $false
            if ($line.StartsWith('@@')) {
                $isWhitelist = $true
                $line = $line.Substring(2)
            }
            
            #[步骤3: 处理 $ 修改符限定条件 ]
            # （例: ||evil.com^$image 只提取 evil.com 把它放进屏蔽或通行范围以供DNS底层运行！）
            $modIndex = $line.IndexOf('$')
            if ($modIndex -ge 0) { $line = $line.Substring(0, $modIndex) }
            
            # [去除多余后缀标志（类似'^' 结束分隔标记符） ]
            $line = $line.TrimEnd('^')

            $domainCandidate = ""

            # [提取方案分类检查开始 ]
            # 情境A: 符合标准的 Adblock ( || 前置规则 ) 
            if ($line.StartsWith('||')) {
                $possibleTarget = $line.Substring(2)
                # !!防误杀原则!!
                # 我们过滤了不能原生在 clash-domain 生效并导致灾难的部分URL链接(不应当有含 '/'的基于全路径处理的规则存在和通配*)
                if (-not $possibleTarget.Contains('/') -and -not $possibleTarget.Contains('*')) {
                    $domainCandidate = $possibleTarget
                }
            }
            # 情境B: Hosts文件类型屏蔽方式匹配
            elseif ($line -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                $domainCandidate = $Matches[1]
            }
            # 情境C: 类似 Dnsmasq address 或 server路由表支持拦截
            elseif ($line -match '^(?:address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(/.*)?$') {
                $domainCandidate = $Matches[1]
            }
            # 情境D: 其自身只存在一段非常标准的单纯无额外内容的单点直白主/二级完整纯英文数字网络顶级后缀组成者
            elseif ($line -match '^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                $domainCandidate = $Matches[1]
            }

            # 执行有效性加入：使用预定义的DNS判断确保没有脏格式写进结果集
            if ($domainCandidate.Length -gt 0 -and (Is-ValidDNSDomain -domain $domainCandidate)) {
                if ($isWhitelist) {
                    $excludedDomains.Add($domainCandidate) | Out-Null
                } else {
                    $uniqueRules.Add($domainCandidate) | Out-Null
                }
            }
        }
    }
    catch {
        Write-Host "处理URL发生失败: $url -> $_" -ForegroundColor Red
        Add-Content -Path $logFilePath -Value "[!] 获取解析遇到失联及意外问题: $_"
    }
}

# Clash使用 Domain集合后缀策略，去剔除存在于排除网单的特定存在名单，保留真实有害过滤数据：
# 我们要求 $finalRules 得到有效的数据。
$finalRules = [System.Collections.Generic.List[string]]::new()
foreach ($blockedDomain in $uniqueRules) {
    if (-not $excludedDomains.Contains($blockedDomain)) {
        # 注意: 我们为Clash Meta配置统一转换 Domain Suffix写法 '+.domain.com'
        # + 表示 同时也去匹配这个顶级基础根（包含根的请求或他之下的任何无限泛播级配下主线路由拦截都包括在内！即实现`通配处理子集所有分支请求的请求要求!`）
        $finalRules.Add("- '+.$blockedDomain'")
    }
}

$finalRules.Sort() # 根据按首位对整理排列
$ruleCount = $finalRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 在最终的payload部分中加入生成的节点信息格式：
$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的纯正无污规则域名列表。已经历原生通用修正与精剪去无效路径机制处理。(确保降低非网络协议栈规则在Clash环境造成的过度误拦现象)
# Generated on: $generationTime
# Auto Process By Optimized-Action
# Total Domain Prefix / Core Sets Filter rules generated amount values currently active matching are computed to at least evaluated entries counts size equals total matching result payload set amounts entry block quantity sum of: $ruleCount entries lines block sizes values...

payload:
$($finalRules -join "`n")
"@

# 使用 UTF8不带BOM无签名流的方式存入文本!这是必须做的,以免部分平台的解析器核心出BUG产生 "yaml parse format crash" 解析识别报修现象的问题 : 
$utf8NoBOM = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outputPath, $textContent, $utf8NoBOM)

Write-Host "`n处理完毕!" -ForegroundColor Green
Write-Host "产生的排去重复白名单干净的广告及分析有效禁止规则项: $ruleCount 列表配置清单完成创建！"
Add-Content -Path $logFilePath -Value "`nTotal Output clean verified safe rule generation valid payload valid format entries successfully evaluated limits reached total completed : $ruleCount "
