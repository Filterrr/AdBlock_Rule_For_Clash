# Title: AdBlock_Rule_For_Clash (最终极致优化抗杀保网版)
# Description: 自动采集、极限去重（过滤多余子域名）、防误杀（排除一级主域名）的 mihomo 规则生成器

$EnableRootDomainDrops = $true

# === 配置采集源 ===
$urlList = @(
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt"
)

$outputPath = "$PSScriptRoot/adblock_reject.yaml"

# 使用更快的 HttpClient
$httpClient = [System.Net.Http.HttpClient]::new()
$httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) mihomo-rule-gen/1.0")

$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains =[System.Collections.Generic.HashSet[string]]::new()

# --- 核心判定：是否为一级主域名 (优化算法：计算点号数量替代Split) ---
function Is-FirstLevelCoreDomain ([string]$d) {
    $dotCount = $d.Length - $d.Replace(".", "").Length
    if ($dotCount -le 1) { return $true }
    if ($dotCount -eq 2 -and $d -match '\.(com|co|net|org|edu|gov|ac|mil)\.(cn|jp|hk|uk|tw|au|kr)$') { return $true }
    return $false
}

# 预编译正则，极大提升大文本循环速度
$regAdblock = [regex]'^\|\|([a-zA-Z0-9*.-]+)\^?'
$regHosts   = [regex]'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$'
$regPlain   = [regex]'^([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})$'

# --- 抓取与处理 ---
foreach ($url in $urlList) {
    Write-Host ">>> 正在处理: $url" -ForegroundColor Yellow
    try {
        $content = $httpClient.GetStringAsync($url).GetAwaiter().GetResult()
        $lines = $content -split "\r?\n"
        
        foreach ($line in $lines) {
            $line = $line.Trim()
            # 过滤空行、注释行及包含 # 的 CSS 隐藏规则
            if ([string]::IsNullOrEmpty($line) -or $line[0] -eq '!' -or $line[0] -eq '[' -or $line.IndexOf('#') -ge 0) { continue }
            
            # 处理白名单 @@
            $isWhitelist = $false
            if ($line.StartsWith('@@')) { 
                $isWhitelist = $true
                $line = $line.Substring(2) 
            }
            
            # 剔除 $ 修饰符后缀
            $idx = $line.IndexOf('$')
            if ($idx -ge 0) { $line = $line.Substring(0, $idx) }

            $domain = $null
            # 匹配提取
            $match = $regAdblock.Match($line)
            if ($match.Success) {
                $domain = $match.Groups[1].Value
            } else {
                $match = $regHosts.Match($line)
                if ($match.Success) {
                    $domain = $match.Groups[1].Value
                } elseif ($line.IndexOf('/') -lt 0 -and $line.IndexOf(':') -lt 0) {
                    $match = $regPlain.Match($line)
                    if ($match.Success) { $domain = $match.Groups[1].Value }
                }
            }

            if (-not [string]::IsNullOrEmpty($domain)) {
                # 剔除前缀通配符，转小写
                $domain = ($domain -replace '^\*?\.?', '').ToLower()
                
                # 核心过滤：如果判定为一级域名且开启了保护，则直接跳过
                if ($EnableRootDomainDrops -and (Is-FirstLevelCoreDomain $domain)) { continue }

                if ($isWhitelist) { [void]$excludedDomains.Add($domain) }
                else { [void]$uniqueRules.Add($domain) }
            }
        }
    } catch { Write-Host "[ERROR] 获取失败: $url" -ForegroundColor Red }
}

Write-Host ">>> 初步提取去重完毕，开始进行[子域名极致精简去重]..." -ForegroundColor Yellow

# --- 剔除白名单 ---
$validDomains =[System.Collections.Generic.List[string]]::new()
foreach ($d in $uniqueRules) {
    if (-not $excludedDomains.Contains($d)) { $validDomains.Add($d) }
}

# --- 核心优化：子域名去重算法 (使用反转字符串 + 字典排序) ---
# 原理：将 ad.baidu.com 反转为 moc.udiab.da，排序后子域名紧挨着父域名。
$reversedDomains = [System.Collections.Generic.List[string]]::new($validDomains.Count)
foreach ($d in $validDomains) {
    $chars = $d.ToCharArray()
    [Array]::Reverse($chars)
    $reversedDomains.Add((-join $chars))
}
$reversedDomains.Sort()

$dedupedReversed = [System.Collections.Generic.List[string]]::new()
$prev = ""
foreach ($r in $reversedDomains) {
    # 如果当前域名以 "上一个域名+点号" 开头，说明是其子域名，直接丢弃
    if ($prev -ne "" -and $r.StartsWith($prev + ".")) { continue }
    $dedupedReversed.Add($r)
    $prev = $r
}

# --- 生成最终符合 mihomo 语法的规则 ---
$outputLines = [System.Collections.Generic.List[string]]::new()
$generationTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ruleCount = $dedupedReversed.Count
$originalCount = $validDomains.Count
$savedCount = $originalCount - $ruleCount

$outputLines.Add("# Title: AdBlock_Rule_For_Clash (mihomo 优化版)")
$outputLines.Add("# Generated: $generationTime")
$outputLines.Add("# Total Rules: $ruleCount (原始规则 $originalCount 条，已精简移除冗余子域名 $savedCount 条)")
$outputLines.Add("# Info: 已剔除一级主域名，保护基础连通性。")
$outputLines.Add("payload:")

# 还原并套用规范化格式
foreach ($r in $dedupedReversed) {
    $chars = $r.ToCharArray()
    [Array]::Reverse($chars)
    $d = -join $chars
    
    # 严格按照 mihomo 规则格式输出
    if ($d.Contains('*')) {
        # 带有中间通配符（如 xbox.*.com），原样包裹输出
        $outputLines.Add("  - `"$d`"")
    } else {
        # 常规域名，使用半角加号进行多级匹配
        $outputLines.Add("  - `"+.$d`"")
    }
}

# --- 无 BOM UTF-8 输出文件 ---
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllLines($outputPath, $outputLines, $utf8NoBom)

Write-Host "--------------------------------------------------------" -ForegroundColor Green
Write-Host "处理完成！成功生成 $ruleCount 条规则 (已精简过滤 $savedCount 条无效子级规则)。" -ForegroundColor Cyan
Write-Host "文件已存至: $outputPath" -ForegroundColor Cyan
