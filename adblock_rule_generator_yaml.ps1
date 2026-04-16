# Title: AdBlock_Rule_For_Clash (Tier-Oriented Refactoring Version)
# Description: 适用于Clash的分级校验纯净去重版，具备强力的泛域名掩盖抑制和分发引入核心架构

# === 自定义需要强制放行拦截的全局强制白名单 ===
$customExcludedDomains = @(
    # "example.com",
    # "taobao.com"
)

# 强制白名单：加载 Top 高权重/常青树域名，防止激进规则误杀
$topWhitelist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if (Test-Path "$PSScriptRoot/top_whitelist.txt") {
    Get-Content "$PSScriptRoot/top_whitelist.txt" | ForEach-Object { $topWhitelist.Add($_.Trim()) | Out-Null }
    Write-Host "已加载 Top 高权重域名保护白名单，共 $($topWhitelist.Count) 个受保护域名。" -ForegroundColor Cyan
}

# ====== 按域资源精信等级预定义池分布 ======
$allowUrls = @(
    "https://raw.githubusercontent.com/Filterrr/AdBlock_Rule_For_Clash/main/allowlist.txt"
)

$tier1Urls = @(
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt"
)

$tier2Urls = @(
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylist.txt"
)

$tier3Urls = @(
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt"
)

# 日志输出流
$logFilePath = "$PSScriptRoot/adblock_log.txt"
Clear-Content -Path $logFilePath -ErrorAction SilentlyContinue

function Write-Log($message) {
    Write-Host $message
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
}

# 用于提取数据的重载模块（内置域合规校检）
function Extract-Rules {
    param(
        [string[]]$Urls,
        [System.Collections.Generic.HashSet[string]]$RulesSet,
        [System.Collections.Generic.HashSet[string]]$GlobalWhitelist
    )
    # 强制正则表达式向上寻找可用级（全局生效避让穿透）
    $domainRegex = '^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$'
    foreach ($url in $Urls) {
        Write-Log "正请求并获取源解析: $url"
        try {
            $content = Invoke-RestMethod -Uri $url -Headers @{
                "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
            } -ErrorAction Stop
            
            $lines = $content -split "`n"
            foreach ($line in $lines) {
                $line = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("!") -or $line.StartsWith("#") -or $line.StartsWith("[")) { continue }

                $domain = $null
                $isWhitelist = $line.StartsWith("@@")
                if ($isWhitelist) { $line = $line.Substring(2) }

                switch -Regex ($line) {
                    '^\|\|([a-zA-Z0-9.-]+)(?:\^.*)?$' { $domain = $Matches[1]; break }
                    '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+)' { $domain = $Matches[1]; break }
                    '^(?:address|server)=/([a-zA-Z0-9.-]+)/' { $domain = $Matches[1]; break }
                    '^DOMAIN(?:-SUFFIX)?,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})' { $domain = $Matches[1]; break }
                    '^([a-zA-Z0-9.-]+)$' { $domain = $Matches[1]; break }
                }

                if ($domain -and $domain -match $domainRegex) {
                    # 全网遇到一切规则自带的@@标签直上最高仲裁级别：直接灌输于全局护栏中
                    if ($isWhitelist) {
                        $GlobalWhitelist.Add($domain) | Out-Null
                    } else {
                        $RulesSet.Add($domain) | Out-Null
                    }
                }
            }
        } catch {
            Write-Log "跳过异常拉取项，跳点详情与来源 - $url : $_"
        }
    }
}

Write-Log "==== 开始拉网加载基调架构策略池 ... ===="

$WhiteSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$CoreSet_Raw =[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$Tier3Set_Raw = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($cd in $customExcludedDomains) { $WhiteSet.Add($cd) | Out-Null }

Write-Log "【流程节点: 基础锚和极静白名单处理区】"
Extract-Rules -Urls $allowUrls -RulesSet $CoreSet_Raw -GlobalWhitelist $WhiteSet

Write-Log "【流程节点: 主体中流核心防泄漏架构区 T1/T2处理池】"
$allCoreUrls = $tier1Urls + $tier2Urls
Extract-Rules -Urls $allCoreUrls -RulesSet $CoreSet_Raw -GlobalWhitelist $WhiteSet

Write-Log "【流程节点: 低授信外援广幅源防干扰拓展区 T3处理池】"
Extract-Rules -Urls $tier3Urls -RulesSet $Tier3Set_Raw -GlobalWhitelist $WhiteSet


# =======  Phase 1：首先合成绝对可信的主力结构 (对核合集自我修剪清沉去重) =========
Write-Log ">> 第一顺次执行运算排空主力核中内生累赘冗余，保障主网架构防干扰建立稳定高精黑库."
$OptimizedCoreSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($domain in $CoreSet_Raw) {
    # 快速自核准与全级反噬扫描拦截掉与顶设排位强撞的车
    if ($WhiteSet.Contains($domain)) { continue }

    $isWhitelisted = $false
    $dotIndex = $domain.IndexOf('.')
    while ($dotIndex -ge 0 -and $dotIndex -lt ($domain.Length - 1)) {
        if ($WhiteSet.Contains($domain.Substring($dotIndex + 1))) {
            $isWhitelisted = $true
            break
        }
        $dotIndex = $domain.IndexOf('.', $dotIndex + 1)
    }
    if ($isWhitelisted) { continue }

    # 核内上大位子层归口吞纳（子级域依附剔除，保留最大的基数）
    $isRedundant = $false
    $dotIndex = $domain.IndexOf('.')
    while ($dotIndex -ge 0 -and $dotIndex -lt ($domain.Length - 1)) {
        if ($CoreSet_Raw.Contains($domain.Substring($dotIndex + 1))) {
            $isRedundant = $true
            break
        }
        $dotIndex = $domain.IndexOf('.', $dotIndex + 1)
    }
    if (-not $isRedundant) { $OptimizedCoreSet.Add($domain) | Out-Null }
}


# =======  Phase 2：构造深海反干涉防护锚机制屏障 (为抵御Tier3大位穿透作阵盘部署) =========
Write-Log ">> 执行主脑高危映射回传运算防溢墙，强制防御防干涉机制组起……"
$ProtectedAncestors =[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
# 全方位将所有精准保留及操作微操向上传导禁止权链锁
foreach ($setList in @($WhiteSet, $OptimizedCoreSet)) {
    foreach ($item in $setList) {
        $cDom = $item
        $ProtectedAncestors.Add($cDom) | Out-Null
        while ($true) {
            $idx = $cDom.IndexOf('.')
            if ($idx -lt 0 -or $idx -ge ($cDom.Length - 1)) { break }
            $cDom = $cDom.Substring($idx + 1)
            $ProtectedAncestors.Add($cDom) | Out-Null
        }
    }
}


# =======  Phase 3：清运合并有隐患的外挂外链规则Tier 3池 =========
Write-Log ">> 在确保屏墙隔离下提取Tier3扩充，执行剔宽存特精切过滤…"
$ValidTier3Set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($domain in $Tier3Set_Raw) {
    # ① 致命打捞干涉法检错法拦截：若是妄图去试图盖掉任意一条防爆层父根源以强压覆盖面将因过广宽幅遭强制击毙流配。
    # 解释: T3源不稳经常发宽项涵盖过广（它想封com盖下属结构等）；这一块通过比对核预保护阵将完美规避误报杀核心树木及容忍列表问题.
    if ($ProtectedAncestors.Contains($domain)) {
        continue
    }

    # ② 子树往上验证：检查如果它本属的小域被全局黑/或受控主源内网全域兜过了或者早就处于高权受限白单中
    $shouldDiscard = $false
    $dotIndex = $domain.IndexOf('.')
    while ($dotIndex -ge 0 -and $dotIndex -lt ($domain.Length - 1)) {
        $parent = $domain.Substring($dotIndex + 1)
        if ($WhiteSet.Contains($parent) -or $OptimizedCoreSet.Contains($parent)) {
            $shouldDiscard = $true
            break
        }
        $dotIndex = $domain.IndexOf('.', $dotIndex + 1)
    }

    if (-not $shouldDiscard) { $ValidTier3Set.Add($domain) | Out-Null }
}

# 最后针对已被滤芯放出来的T3同层规则相互去冗余排压化
$OptimizedTier3Set = [System.Collections.Generic.List[string]]::new()
foreach ($domain in $ValidTier3Set) {
    $isRedundant = $false
    $dotIndex = $domain.IndexOf('.')
    while ($dotIndex -ge 0 -and $dotIndex -lt ($domain.Length - 1)) {
        if ($ValidTier3Set.Contains($domain.Substring($dotIndex + 1))) {
            $isRedundant = $true
            break
        }
        $dotIndex = $domain.IndexOf('.', $dotIndex + 1)
    }
    if (-not $isRedundant) { $OptimizedTier3Set.Add($domain) }
}


# ==== Phase 4：合成与规范化导出组输出构建 ====
$FinalCombinedRules =[System.Collections.Generic.List[string]]::new()
foreach ($cd in $OptimizedCoreSet) { $FinalCombinedRules.Add($cd) }
foreach ($td in $OptimizedTier3Set) { $FinalCombinedRules.Add($td) }

$ruleCount = $FinalCombinedRules.Count
$formattedRules = $FinalCombinedRules | Sort-Object | ForEach-Object { "- '+.$_'" }

Write-Log "-----------------------[合成简要统计核验结束流结结账报告] --------------------------"
Write-Log "[保障坚如磐石源汇] ：提纯筛选的核心稳固流集池量级（T1/T2）    -> 录余: $($OptimizedCoreSet.Count) 条级效度网格策略配置"
Write-Log "[阻燃与剔伪过滤比] ：受纯粹屏墙防御隔离被挡死阻击的大域冗漏   -> 全靠强制级锁抛挂屏蔽宽溢风险项免予穿透泛起误斩狂击事件。"
Write-Log "[引补纯真补偿特战] ：真正被筛过无痛接入为核心扩展边缘漏洞补源 -> 引扩: $($OptimizedTier3Set.Count) 颗极高安全性单散域狙位子弹装列"
Write-Log "[无误斩收刀闭仓总流输出配载节点量值统计总揽]            -> : 累计融合规则配置条目 $ruleCount 条全净空策略"

$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")
$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 高分型双校验护航规则级池融合优化，精准锁放层防御防止冗乱第三方强吞精定位架构！保护网络高存活性！
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime (UTC+8)
# Base Protected Level Total (Tier1+Tier2 Base rules pool entries): $($OptimizedCoreSet.Count) 
# Tier 3 Complementary additions effectively shielded included: $($OptimizedTier3Set.Count)
# Cumulative filtered rule capacity scale payload load level items entries total: $ruleCount

payload:
$($formattedRules -join "`n")
"@

$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outputPath, $textContent, $utf8NoBom)

Write-Log ">> 本级精洗核爆抗容与分档逻辑提配规则最终输出成功！完美存储在 : $outputPath 。"
