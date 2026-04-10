# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash

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

# 路径定义
$logFilePath = "$PSScriptRoot/adblock_log.txt"
$outputPath = "$PSScriptRoot/adblock_reject.yaml"

# 1. 初始化数据结构 (指定忽略大小写，防止同一个域名因大小写不同被重复计算)
$comparer = [System.StringComparer]::OrdinalIgnoreCase
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new($comparer)
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new($comparer)

# 2. 预编译正则表达式 (极大提升循环内的匹配速度)
$regexOpts = [System.Text.RegularExpressions.RegexOptions]::Compiled
$regAdblock = [regex]::new('^\|\|([a-zA-Z0-9.-]+)\^$', $regexOpts)
$regDnsmasq = [regex]::new('^(?:address|server)=/([a-zA-Z0-9.-]+)/', $regexOpts)
$regDomainOnly = [regex]::new('^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', $regexOpts)

# 初始化 HttpClient 用于快速且稳定的下载
$httpClient = [System.Net.Http.HttpClient]::new()
$httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

foreach ($url in $urlList) {
    Write-Host "正在处理: $url"
    Add-Content -Path $logFilePath -Value "[$(Get-Date -Format 'HH:mm:ss')] 正在处理: $url"
    try {
        $content = $httpClient.GetStringAsync($url).GetAwaiter().GetResult()
        
        # 使用 StreamReader 逐行读取内存中的字符串，比 -split 更节省内存
        $stringReader = [System.IO.StringReader]::new($content)
        
        while ($null -ne ($line = $stringReader.ReadLine())) {
            $line = $line.Trim()
            
            # 跳过空行和注释行
            if ($line.Length -eq 0 -or $line[0] -eq '!' -or $line[0] -eq '#' -or $line[0] -eq '[') { continue }

            # --- 白名单处理 ---
            if ($line.StartsWith('@@')) {
                # 简化白名单提取
                if ($line -match '@@\|\|([a-zA-Z0-9.-]+)\^?') {
                    $excludedDomains.Add($Matches[1]) > $null
                }
                continue
            }

            $domain = $null

            # --- 黑名单提取 (按命中概率排序，优先判断简单的) ---
            if ($line.StartsWith('0.0.0.0 ')) {
                $domain = $line.Substring(8).Trim()
            }
            elseif ($line.StartsWith('127.0.0.1 ')) {
                $domain = $line.Substring(10).Trim()
            }
            elseif ($line.StartsWith('::1 ')) {
                $domain = $line.Substring(4).Trim()
            }
            elseif ($line.StartsWith(':: ')) {
                $domain = $line.Substring(3).Trim()
            }
            else {
                $match = $regAdblock.Match($line)
                if ($match.Success) { $domain = $match.Groups[1].Value }
                else {
                    $match = $regDnsmasq.Match($line)
                    if ($match.Success) { $domain = $match.Groups[1].Value }
                    else {
                        $match = $regDomainOnly.Match($line)
                        if ($match.Success) { $domain = $match.Groups[1].Value }
                    }
                }
            }

            # --- 极速 DNS 规范验证并加入集合 ---
            # 使用底层 CheckHostName 方法，比正则验证快得多
            if ($null -ne $domain -and [System.Uri]::CheckHostName($domain) -eq 'Dns') {
                $uniqueRules.Add($domain) > $null
            }
        }
        $stringReader.Dispose()
    }
    catch {
        Write-Host "处理 $url 时出错: $_" -ForegroundColor Red
        Add-Content -Path $logFilePath -Value "处理 $url 时出错: $_"
    }
}

$httpClient.Dispose()

Write-Host "下载与解析完成，开始执行去重与排序..." -ForegroundColor Cyan

# 3. 极速集合运算：将白名单中的域名直接从黑名单集合中剔除 (耗时几乎为 0)
$uniqueRules.ExceptWith($excludedDomains)

# 将集合转换为数组并排序
$finalRulesList = [System.Linq.Enumerable]::ToList($uniqueRules)
$finalRulesList.Sort()

$ruleCount = $finalRulesList.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

Write-Host "开始生成 YAML 载荷文件..." -ForegroundColor Cyan

# 4. 使用 StreamWriter 流式高速写入文件
$writer = [System.IO.StreamWriter]::new($outputPath, $false, [System.Text.Encoding]::UTF8)

try {
    # 写入头部信息
    $writer.WriteLine("# Title: AdBlock_Rule_For_Clash")
    $writer.WriteLine("# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀")
    $writer.WriteLine("# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash")
    $writer.WriteLine("# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0")
    $writer.WriteLine("# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0")
    $writer.WriteLine("# Generated on: $generationTime")
    $writer.WriteLine("# Generated AdBlock rules")
    $writer.WriteLine("# Total entries: $ruleCount")
    $writer.WriteLine("")
    $writer.WriteLine("payload:")
    
    # 高速遍历写入
    foreach ($domain in $finalRulesList) {
        $writer.WriteLine("  - '+.$domain'")
    }
}
finally {
    $writer.Dispose()
}

Write-Host "生成的有效规则总数: $ruleCount" -ForegroundColor Green
Add-Content -Path $logFilePath -Value "[$(Get-Date -Format 'HH:mm:ss')] 执行完毕. Total entries: $ruleCount"
