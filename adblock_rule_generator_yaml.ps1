# Title: AdBlock_Rule_For_Clash (Layered Pure/Optimized Core)
# Description: 适用于Clash的分级纯净层拦截规则集，执行防连坐与脏数据智能规避的高效筛选算法
# ======= 分级分权机制体系设计 =======

# 1. 绝对强制的免疫通行权（人工强制放行顶级策略，自动继承惠泽全部源校验与各级分枝网络）
$customExcludedDomains = @(
    # "example.com",
    # "taobao.com"
)

# 2. 【黄金源 Tier 1】顶级信誉基线列表（具有严格核审规则避免随意诛杀）
$tier1Urls = @(
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt"
)

# 3. 【优质区补充 Tier 2】可靠社区贡献/特定中方环境补给列表 (被划定在不可置疑范畴内，共同合成本地基础墙)
$tier2Urls = @(
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylist.txt"
)

# 4. 【激进衍生池 Tier 3】三方无情拉黑名单与散装拦截流集锦 (包含极其容易引发错误全拦父级主域导致网页瘫痪之杂质风险节点源，因此在下端通过校验引擎剔除误拦截倾向)
$tier3Urls = @(
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt"
)


# ================== 初始化基底运行容器结构（高性能 O(1) 检索优化）====================
$logFilePath = "$PSScriptRoot/adblock_log.txt"
Clear-Content -Path $logFilePath -ErrorAction SilentlyContinue

function Write-Log($message) {
    Write-Host $message
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
}

# 忽略大小写提升正则及比对效率
$excludedDomains =[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$coreRules       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$t3Rules         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$domainRegex     = '^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$'

foreach ($cd in $customExcludedDomains) { $excludedDomains.Add($cd) | Out-Null }


# ====== 【源站请求/分流器模组】=============
function Invoke-ParseTierRule {
    param([string]$TierLevel, [string[]]$Urls,[System.Collections.Generic.HashSet[string]]$TargetDB)
    foreach ($url in $Urls) {
        Write-Log "[$TierLevel] 获取更新池：$url"
        try {
            $content = Invoke-RestMethod -Uri $url -TimeoutSec 20 -Headers @{
                "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
            }
            $lines = $content -split "`n"
            foreach ($line in $lines) {
                $line = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("!") -or $line.StartsWith("#") -or $line.StartsWith("[")) { continue }

                $domain = $null
                $isWhitelist = $line.StartsWith("@@")
                if ($isWhitelist) { $line = $line.Substring(2) }

                switch -Regex ($line) {
                    '^\|\|([a-zA-Z0-9.-]+)(?:\^.*)?$'                        { $domain = $Matches[1]; break }
                    '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+)'   { $domain = $Matches[1]; break }
                    '^(?:address|server)=/([a-zA-Z0-9.-]+)/'                 { $domain = $Matches[1]; break }
                    '^DOMAIN(?:-SUFFIX)?,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'  { $domain = $Matches[1]; break }
                    '^([a-zA-Z0-9.-]+)$'                                     { $domain = $Matches[1]; break }
                }

                if ($domain -and $domain -match $domainRegex) {
                    # 白名单是穿透无界规则，强制上浮到高纬全图排除层发挥避让效果 
                    if ($isWhitelist) { $excludedDomains.Add($domain) | Out-Null } 
                    else { $TargetDB.Add($domain) | Out-Null }
                }
            }
        }
        catch { Write-Log "[$TierLevel] 执行解析 $url 的过程产生阻塞意外，错误原因：$_" }
    }
}

Write-Log ">>>>>>  一. 并网接入口任务启航...（进行分类多流爬虫提纯拦截体中） "
Invoke-ParseTierRule -TierLevel "核心T1组" -Urls $tier1Urls -TargetDB $coreRules
Invoke-ParseTierRule -TierLevel "高标T2组" -Urls $tier2Urls -TargetDB $coreRules
Invoke-ParseTierRule -TierLevel "脏池T3组" -Urls $tier3Urls -TargetDB $t3Rules


# ====== 【阶段 Phase 1】：T1/T2（强制稳态黄金核心规则体系运算构架，受最强优先级认可） =============
Write-Log ">>>>>>  二. 执行深算提取: 凝练合并优化的纯洁[并集 Core 集块], 配置强白免与受体宽范围连环覆盖检测…… "
$finalRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$coreParentsRestricted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($domain in $coreRules) {
    if ($excludedDomains.Contains($domain)) { continue }

    $isWhitelisted = $false
    $parentDomainsList =[System.Collections.Generic.List[string]]::new()
    
    $dotIndex = $domain.IndexOf('.')
    while ($dotIndex -ge 0 -and $dotIndex -lt ($domain.Length - 1)) {
        $parentDomain = $domain.Substring($dotIndex + 1)
        $parentDomainsList.Add($parentDomain)
        if ($excludedDomains.Contains($parentDomain)) {
            $isWhitelisted = $true
            break
        }
        $dotIndex = $domain.IndexOf('.', $dotIndex + 1)
    }
    
    if ($isWhitelisted) { continue }

    # 同族核心的纯度重压——排布验证顶级过滤，如果已有父亲拦着下面细致冗杂域名就没有存着的需求
    $isRedundant = $false
    foreach ($pd in $parentDomainsList) {
        if ($coreRules.Contains($pd)) {
            $isRedundant = $true
            break
        }
    }

    # 这是在高级 T1 / T2 名单内提炼筛选完成过核心净体
    if (-not $isRedundant) {
        $finalRules.Add($domain) | Out-Null
        # ✨关键分层限制手段点！【由于T1/T2十分收敛靠谱且极有可能细化击杀“track.api.com”但不想整网封存"api.com"】,那么所有这些留有缝隙与子域细查痕迹的安全主干全列装护卫装甲内:
        foreach ($pd in $parentDomainsList) {
            $coreParentsRestricted.Add($pd) | Out-Null
        }
    }
}
Write-Log "     --核心纯洁列表提取完成，沉淀精校过滤词条 [$($finalRules.Count)] 个"
Write-Log "     --启动激进免罪装甲网络（针对可靠主级）：获取 [$($coreParentsRestricted.Count)] 项受高级名单逻辑背书庇护"


# ====== 【阶段 Phase 2】：“隔离区式入池补充法”，安全挂载 T3 源规则的交叉验证。 =====
Write-Log ">>>>>>  三. 精致接续: 对具有狂放激进、可能带来致命瘫痪效应导致[全家株连风险]的三源节点，启用越过宽体排他机制和冗错校验! "
$statsT3_Add = 0; $statsT3_RejectWhite = 0; $statsT3_RejectRedun = 0; $statsT3_RejectAggressive = 0

foreach ($domain in $t3Rules) {
    if ($excludedDomains.Contains($domain)) { $statsT3_RejectWhite++; continue }
    
    $isWhitelisted = $false
    $t3ParentsList = [System.Collections.Generic.List[string]]::new()
    $dotIndex = $domain.IndexOf('.')
    
    while ($dotIndex -ge 0 -and $dotIndex -lt ($domain.Length - 1)) {
        $parentDomain = $domain.Substring($dotIndex + 1)
        $t3ParentsList.Add($parentDomain)
        if ($excludedDomains.Contains($parentDomain)) {
            $isWhitelisted = $true
            break
        }
        $dotIndex = $domain.IndexOf('.', $dotIndex + 1)
    }
    if ($isWhitelisted) { $statsT3_RejectWhite++; continue }
    
    # 无需给当前已覆盖重复干重工添乱
    if ($finalRules.Contains($domain)) { $statsT3_RejectRedun++; continue }
    
    $isRedundant = $false
    foreach ($pd in $t3ParentsList) {
        if ($finalRules.Contains($pd)) {
            $isRedundant = $true
            break
        }
    }
    if ($isRedundant) { $statsT3_RejectRedun++; continue }

    # ✨核心精华逻辑：激进规则阻滞墙（如果脏活强源想通过无情扩大泛规则"诛灭九族"的模式来过滤`example.com`整体的话）：
    # 比如在基础核表被安全豁免过的上层受体，此时绝对不能容忍你全杀了，所以判定它具备恶意危险从而踢走它的权限尝试。 
    if ($coreParentsRestricted.Contains($domain)) {
        $statsT3_RejectAggressive++
        continue
    }

    $finalRules.Add($domain) | Out-Null
    $statsT3_Add++
}

Write-Log "     --野种补齐行动总览结案！ "
Write-Log "       => 高光成功汲入独立查缺项数目 : $statsT3_Add (可被绝对确信任它放肆而无关全局安宁)。"
Write-Log "       => 精细阻抗 T3白名单干涉拦截量: $statsT3_RejectWhite"
Write-Log "       => 清理丢掉早包含重合拦截无效值: $statsT3_RejectRedun"
Write-Log "       =>[⭐] 高效打掉恶质/致断网防守量: $statsT3_RejectAggressive 个 (保护了主线不受无边界全灭拉闸破坏！)"


# ============ 落笔阶段与文档定稿，出格式转换：Yaml序列 ========
$ruleCount = $finalRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")
Write-Log "整理数据汇率结构中。去除赘余体态节点留量总重定版估值数额量为 => $ruleCount ..."

# 取数据字典化列表集与重定向流式装车格式载片：
$formattedRules = $finalRules | Sort-Object | ForEach-Object { "- '+.$_'" }

$textContent = @"
# Title: AdBlock_Rule_For_Clash 
# Description: 极域抗污分离校验（提炼T1/T2交点容错墙抗泛扫阻断机制护盘处理）防脏防连坐，专适用严酷过滤与自动清杂。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime (UTC+8)
# Multi-Level Pure Defensive AdBlock logic Generated List. Total: $ruleCount. 

payload:
$($formattedRules -join "`n")
"@

$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)[System.IO.File]::WriteAllText($outputPath, $textContent, $utf8NoBom)

Write-Log "全部流水进程作业交棒：终点已部署妥协安全并送达导出源: $outputPath ."
