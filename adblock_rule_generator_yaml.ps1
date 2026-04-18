# Title: AdBlock_Rule_For_Clash
# Description: Clash 广告拦截规则生成脚本
# 功能：自动屏蔽广告，保障网络稳定畅通。

# === 自定义全局白名单 ===
$customExcludedDomains = @(
    # "example.com",
    # "taobao.com"
)

# === 按规则质量分级的订阅源 ===
$allowUrls = @(
    "https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/white.txt"
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
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt"
)

# 日志输出流
$logFilePath = "$PSScriptRoot/adblock_log.txt"
Clear-Content -Path $logFilePath -ErrorAction SilentlyContinue

function Write-Log($message) {
    Write-Host $message
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
}

# 用于提取数据的重载模块（内置域名格式校验）
function Extract-Rules {
    param(
        [string[]]$Urls,
        [System.Collections.Generic.HashSet[string]]$RulesSet,[System.Collections.Generic.HashSet[string]]$GlobalWhitelist
    )
    $domainRegex = '^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$'
    foreach ($url in $Urls) {
        Write-Log "正在获取: $url"
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
                    # 遇到带有 @@ 的白名单规则，直接加入全局白名单
                    if ($isWhitelist) {
                        $GlobalWhitelist.Add($domain) | Out-Null
                    } else {
                        $RulesSet.Add($domain) | Out-Null
                    }
                }
            }
        } catch {
            Write-Log "获取失败，已跳过 - $url : $_"
        }
    }
}

Write-Log "==== 开始初始化设置和本地白名单 ===="

# === 初始化各类集合 ===
$WhiteSet =[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$CoreSet_Raw =[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$Tier3Set_Raw = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# 导入脚本顶部预设的自定义全局白名单
foreach ($cd in $customExcludedDomains) { $WhiteSet.Add($cd) | Out-Null }

# ====== 加载外部核心白名单 ======
# 功能：加载高权重域名白名单（top_whitelist.txt），防止被规则误杀
$topWhitelist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if (Test-Path "$PSScriptRoot/top_whitelist.txt") {
    Get-Content "$PSScriptRoot/top_whitelist.txt" | ForEach-Object { 
        $domain = $_.Trim()
        # 过滤空行和带有 # 的注释内容
        if (-not [string]::IsNullOrWhiteSpace($domain) -and -not $domain.StartsWith("#")) {
            $topWhitelist.Add($domain) | Out-Null
            
            # 将这些域名加入全局白名单，防止被拦截
            $WhiteSet.Add($domain) | Out-Null 
        }
    }
    $successMsg = "成功加载本地高权重白名单文件，共包含 [$($topWhitelist.Count)] 个域名！"
    Write-Host $successMsg -ForegroundColor Cyan
    Write-Log $successMsg
}
# ====== 核心白名单加载完成 ======

Write-Log "【步骤 1: 获取预设及在线全局白名单】"
Extract-Rules -Urls $allowUrls -RulesSet $CoreSet_Raw -GlobalWhitelist $WhiteSet

Write-Log "【步骤 2: 获取基础保护规则 (Tier 1 / Tier 2)】"
$allCoreUrls = $tier1Urls + $tier2Urls
Extract-Rules -Urls $allCoreUrls -RulesSet $CoreSet_Raw -GlobalWhitelist $WhiteSet

Write-Log "【步骤 3: 获取扩展补充规则 (Tier 3)】"
Extract-Rules -Urls $tier3Urls -RulesSet $Tier3Set_Raw -GlobalWhitelist $WhiteSet

# ======= 阶段 1：处理基础规则 (清理去重) =========
Write-Log ">> 正在清理基础规则中的冲突和冗余内容..."
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

    # 移除子域名，只保留父级域名
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

# ======= 阶段 2：构建防误杀保护机制 =========
Write-Log ">> 正在生成重点防护名单，防止重要域名被意外拦截..."
$ProtectedAncestors =[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
# 提取出白名单与核心规则的所有父级域名，确保它们不会被下级规则影响
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

# ======= 阶段 3：过滤并合并扩展规则 (Tier 3) =========
Write-Log ">> 正在检测扩展规则，排除与保护名单冲突的内容..."
$ValidTier3Set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($domain in $Tier3Set_Raw) {
    # 如果扩展规则试图拦截受保护的域名，则直接舍弃该规则：
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

# 再次对剩余的扩展规则进行父级域名去重
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

# ==== 阶段 4：合并规则并生成文件 ====
$FinalCombinedRules =[System.Collections.Generic.List[string]]::new()
foreach ($cd in $OptimizedCoreSet) { $FinalCombinedRules.Add($cd) }
foreach ($td in $OptimizedTier3Set) { $FinalCombinedRules.Add($td) }

$ruleCount = $FinalCombinedRules.Count
$formattedRules = $FinalCombinedRules | Sort-Object | ForEach-Object { "- '+.$_'" }

Write-Log "-----------------------[最终统计结果] --------------------------"
Write-Log "[基础规则] : 提纯并保留的基础拦截规则   -> 共计 : $($OptimizedCoreSet.Count) 条"
Write-Log "[保护机制] : 本地白名单防误杀保护       -> 已成功生效"
Write-Log "[扩展规则] : 补充未冲突的附加扩展规则   -> 共计 : $($OptimizedTier3Set.Count) 条"
Write-Log "[最终统计] : 规则库合并完毕             -> 总计生成 : $ruleCount 条规则配置"

$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")
$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 适用于 Clash（premium 与 mihomo）的广告域名拦截 RULE-SET 规则集，每天更新一次
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime (UTC+8)
# Protected Whitelist domains Count: $($topWhitelist.Count) 
# Total Payload Items Count: $ruleCount

payload:
$($formattedRules -join "`n")
"@

$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outputPath, $textContent, $utf8NoBom)

Write-Log ">> 广告拦截规则处理完成！已导出为无 BOM 格式，文件保存在: $outputPath"
