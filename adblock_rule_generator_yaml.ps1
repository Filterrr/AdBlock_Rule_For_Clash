# Title: AdBlock_Rule_For_Clash (Tier-Oriented Refactoring Version with TOP Protection)
# Description: 高分型双校验与顶配重级核锁定版规则生成架构
# 强防御与分挡纯净化模式：自动屏蔽冗杂穿透干扰保障主力基网稳定畅通

# === 自定义需要强制放行拦截的全局强制白名单 ===
$customExcludedDomains = @(
    # "example.com",
    # "taobao.com"
)

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
        [System.Collections.Generic.HashSet[string]]$RulesSet,[System.Collections.Generic.HashSet[string]]$GlobalWhitelist
    )
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

Write-Log "==== 开始装载架构初始化与本地核心强制豁免策略库 ... ===="

# === 初始化各类集合容器 ===
$WhiteSet =[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$CoreSet_Raw =[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$Tier3Set_Raw = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# 导入用户定义的脚本自带防拦截变量配置
foreach ($cd in $customExcludedDomains) { $WhiteSet.Add($cd) | Out-Null }

# ======[核心扩展接入区：开始接入] ======
# 强制白名单：加载 Top 高权重/常青树域名，防止激进规则误杀
$topWhitelist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if (Test-Path "$PSScriptRoot/top_whitelist.txt") {
    Get-Content "$PSScriptRoot/top_whitelist.txt" | ForEach-Object { 
        $domain = $_.Trim()
        # 排空 txt 内可能的空行或者#打头注释防止错误读录
        if (-not [string]::IsNullOrWhiteSpace($domain) -and -not $domain.StartsWith("#")) {
            $topWhitelist.Add($domain) | Out-Null
            
            # 【重点】同步写入脚本最终总架构级的白名单中($WhiteSet)确保彻底阻绝所有底层误杀!
            $WhiteSet.Add($domain) | Out-Null 
        }
    }
    $successMsg = "已加载本地 Top 高权重域名常青树保护白名单文件，并向内环打下 [$($topWhitelist.Count)] 根金钢神锁阵钉！"
    Write-Host $successMsg -ForegroundColor Cyan
    Write-Log $successMsg
}
# ====== [核心扩展接入区：结语] ======

Write-Log "【流程节点: 全局白名单预设处理组装获取】"
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

    # 核内上大位子层归口吞纳（子级域依附剔除）
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

# =======  Phase 2：构造深海反干涉防护锚机制屏障 (保障 Top 文件永不可逆向掩蔽) =========
Write-Log ">> 强制启用双向白名单（Top 常青库参与构建安全屋节点...）执行防御倒传禁锢"
$ProtectedAncestors =[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
# 全方位将所有精准保留与你的本地常青高权顶位结构链统通列出安全神仙打锁禁表区
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
Write-Log ">> 对边缘扩张 Tier 3 执行禁表核检过滤 (Top 源已生成最硬抗击护板以迎战测试！)......"
$ValidTier3Set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($domain in $Tier3Set_Raw) {
    # 你的高权限白单如果在 Tier 3 中以过大父根的越权妄图抹过时——即遭彻底踢配处理拦截以阻击崩溃点触发：
    if ($ProtectedAncestors.Contains($domain)) {
        continue
    }

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

# 再执行外联同排并排减废运算优化运算池层叠堆集冗灾减缩
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

Write-Log "-----------------------[全库统计及最终防暴源结算终查明列] --------------------------"
Write-Log "[保障坚如磐石源汇] ：提纯精防筛选全域受限防爆量级 (T1/T2)       -> 合录 : $($OptimizedCoreSet.Count) 个条配置效格区格"
Write-Log "[受持顶级架构常青盾]: 被 Top源完全笼护与保护未爆高受波及项级漏斗    -> Top权阵生效抗压防护源点护体."
Write-Log "[引补外环偏偏辅助缘]: 在无威胁状态真正补充接融防守偏向缘散型网池区      -> 吸纳 : $($OptimizedTier3Set.Count) 个点项外链游项配单子网网兜落库。 "
Write-Log "[结算落合高信抗核总域规则配流汇接清账终载量值配定全揽概测]:    => 合聚出结  : $ruleCount 全集策略包！！"

$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")
$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash（premium核心与mihomo核心）的广告域名拦截RULE-SET规则集，每天更新一次
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime (UTC+8)
# Protected Constant Safe Tree Local-Binds Items Applied ($($topWhitelist.Count)) 
# Total Payload Load Items List Count Generation Export : $ruleCount

payload:
$($formattedRules -join "`n")
"@

$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outputPath, $textContent, $utf8NoBom)

Write-Log ">> 本系统运行级核防、广控无损分层机制最终无Bom抗灾策略生成落地存储已完成 -> 输出定于在位置 ： $outputPath ！"
