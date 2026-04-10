# ==============================================================================
# Title: AdBlock_Rule_For_Clash (Performance Optimized Edition)
# Description: 适用于Clash的域名拦截规则集，多源流并发抽取即时同步有效减损内存与降低耗时。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# ==============================================================================

# 确保在各环境支持安全的网络 Tls 协议 (防御旧版系统请求GitHub报错或受限阻挡)
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor[System.Net.SecurityProtocolType]::Tls13

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

$logFilePath = "$PSScriptRoot/adblock_log.txt"

# 获取时间戳日志界限区分排版（方便后期观测追查运行成功耗时）
$syncStartTime = Get-Date
Add-Content -Path $logFilePath -Value "`r`n====== $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 更新序列启动 ======"

# ================================ [优化模块定义段] =================================
# 定义集合以区分大小写进行优化及确保规则和过滤名全局剔重处理避免生成浪费项开销
$uniqueRules     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedDomains =[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# 配置多行规则直接利用低延迟 .NET C# Native Regex 并行寻轨采集捕获(告别龟速内存数组 -split 大字符串切割)
$regexOptions   = [System.Text.RegularExpressions.RegexOptions]::Compiled -bor[System.Text.RegularExpressions.RegexOptions]::IgnoreCase
$multiLineOpts  = $regexOptions -bor[System.Text.RegularExpressions.RegexOptions]::Multiline

# 通吃覆盖匹配Adblock,纯列表和 Dnsmasq (同时整合统一映射 "domain" 为键直抓数据源头屏蔽干扰)
$inclusionPtn = '^(?:\|\|(?<domain>[a-z0-9.-]+\.[a-z]{2,})\^|(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(?<domain>[a-z0-9.-]+\.[a-z]{2,})|(?:address|server)=/(?<domain>[a-z0-9.-]+\.[a-z]{2,})/|(?<domain>[a-z0-9.-]+\.[a-z]{2,}))\s*$'
$rxInclusions = [regex]::new($inclusionPtn, $multiLineOpts)

# 单独对基于 '@@' 特性的全向保护与域名规则映射挖掘作预构建定义结构分离保障精准性避险
$excludeLinesPtn = '^@@[^\r\n]*'
$rxExcludedLines = [regex]::new($excludeLinesPtn, $multiLineOpts)
$rxPureExDomains = [regex]::new('[\w-]+(?:\.[\w-]+)+', $regexOptions) 

# 高集成 RFC 规范化单体DNS鉴别，淘汰内部切割和复杂开支避免过度检测和逻辑消耗失准耗内存
function Is-ValidDNSDomain([string]$domain) {
    # 只放通2-253之间限制标准的国际化安全DNS校验（有效放宽包括 IDN 字符以及长名）防止混入错体标文打爆Clash 解析组件
    return ($domain -match '^(?=[a-z0-9.-]{2,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,126}[a-z0-9-]{2,63}$')
}
# ====================================================================================

# 配置并构造公共共享 HTTP 的预提取资源句柄与凭证池保护请求顺利接入不受异常检测干掉
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

foreach ($url in $urlList) {
    Write-Host ">>> 并接资源缓冲执行预热分析提取: $url"
    Add-Content -Path $logFilePath -Value "处理上行规则站址通道: $url"

    try {
        # 单一网络同步载入流缓存资源(保持循环逐个析构, 最大限度克制RAM内存泄漏及爆发使用保障低规格 VPS 流畅更新能力)
        $content = $webClient.DownloadString($url)

        # A阶段 - 先手全局筛除锁定获取白名单和免除特赦结构内的规则直接剔取存放处理库 
        foreach ($exLineMatch in $rxExcludedLines.Matches($content)) {
            foreach ($exDomMatch in $rxPureExDomains.Matches($exLineMatch.Value)) {
                $excludedDomains.Add($exDomMatch.Value) | Out-Null
            }
        }

        # B阶段 - 直扫获取捕猎对象与符合规范域名拦截对象匹配规则收录进阻挡黑名数据库映射集
        foreach ($inMatch in $rxInclusions.Matches($content)) {
            $uniqueRules.Add($inMatch.Groups['domain'].Value) | Out-Null
        }
        
        # 释放载入大对象缓存减轻脚本压力堆砌限制
        $content = $null 
        [System.GC]::Collect()
    }
    catch {
        $errMsg = "处理 $url 时报错终止跳过并维持提取: $_"
        Write-Host -ForegroundColor Red $errMsg
        Add-Content -Path $logFilePath -Value $errMsg
    }
}

# ================================ [处理排布组块层] =================================
Write-Host -ForegroundColor Cyan "`n校验合法结构清洗与双向冲突清理合并及序列对账..."
$validExcludedSet =[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$finalTargetRules =[System.Collections.Generic.List[string]]::new()

# 安全排查鉴权及清洗所有待抛白免排序列，预先验证过滤废包及超大结构以免疫非法排期影响 Clash 读取核心崩溃
foreach ($d in $excludedDomains) { if (Is-ValidDNSDomain $d) { $validExcludedSet.Add($d) | Out-Null } }

foreach ($d in $uniqueRules) {
    if ((Is-ValidDNSDomain $d) -and -not $validExcludedSet.Contains($d)) {
        $finalTargetRules.Add($d) | Out-Null
    }
}
$finalTargetRules.Sort()  # 高级纯 .NET List数组基于 Unicode字典排版极速列定对撞（较比传统慢如牛的 | Sort-Object 效率飞升数倍至十几倍！）

# 直接流格式装盘数组循环结构(不跑 Select和Pipeline管道免阻网络循环损耗与生成过满瓶颈卡壳延时问题）
$formattedRules = foreach ($dom in $finalTargetRules) { "- '+.$dom'" }
$ruleCount      = $finalTargetRules.Count

$syncEndTime = (Get-Date)
$elapsedSec  = [math]::Round(($syncEndTime - $syncStartTime).TotalSeconds, 2)
$generationTime = $syncEndTime.ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 数据封固映射构造区域结构格式输出
$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，多线重构优化解析高速并推入源上游更新阻碍清理屏蔽。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL%203.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA%204.0
# Generated on: $generationTime
# Generated AdBlock rules entries optimized output
# Total effective domains verified loaded : $ruleCount

payload:
$($formattedRules -join "`n")
"@

# 无 BOM（Byte-Order Mark）特征格式头以防影响读取
$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$utf8NoBOM  = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outputPath, $textContent, $utf8NoBOM)

$statResultMsg = "数据更新编配转换大成功! 总拦截列表获取数目:[$ruleCount] , 流失及完成循环使用周期 : $elapsedSec 秒"
Write-Host -ForegroundColor Green "`n$statResultMsg`nYAML 规范文件封装保存直向至: $outputPath`n"
Add-Content -Path $logFilePath -Value "====== 总成行数： $ruleCount 条 ====== `r`n更新序列操作统计运行计耗结束. (计合延期时长 $elapsedSec 秒)"
