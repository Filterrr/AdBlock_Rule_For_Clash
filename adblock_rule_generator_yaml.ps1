# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，按Clash-Meta原生模式过滤CSS以及兼容各标识匹配符号拦截，确保即时同步上游且将白名单映射降低网络直联层误杀。修复处理病态带 '.' 通用格式匹配。
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

# 日志文件路径
$logFilePath = "$PSScriptRoot/adblock_log.txt"

# 统一创建 WebClient 获取资源对象并伪装 Header 以增加下行安全性与成功率
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

# 定义两个集合收集：拦截主列表 和 排错白名单防碰瓷
$uniqueRules =[System.Collections.Generic.HashSet[string]]::new()
$excludedDomains =[System.Collections.Generic.HashSet[string]]::new()

# DNS格式和拦截字符串防沉淀检验增强
function Is-ValidRuleDomain($domain) {
    if ([string]::IsNullOrWhiteSpace($domain) -or $domain.Length -gt 253 -or $domain.Length -lt 2) { 
        return $false 
    }
    
    # 严格排除类似以 '.x.xxx', '.domain' 以及以 `-` 短杠引发的结构破坏畸形的残渣地址。 
    if ($domain.StartsWith('.') -or $domain.EndsWith('.') -or $domain.StartsWith('-') -or $domain.EndsWith('-')) {
         return $false
    }

    # 如果有连续相碰导致多个圆点例如 "a..cn"，视为不符合逻辑规则彻底驱逐拦截队列不给Meta层带坑。
    if ($domain.Contains('..')) {
         return $false
    }

    # 让含有合法泛匹配统配符的合法格式(星号*)、通用中划横线、常规域名平滑纳入。异常乱字符则拦截过滤报错！
    if ($domain -notmatch '^[a-zA-Z0-9*.-]+$') {
        return $false
    }
    return $true
}

# 遍历地址开启分析与精妙转接提取
foreach ($url in $urlList) {
    Write-Host "正在拉取解析处理源集: $url"
    Add-Content -Path $logFilePath -Value "正在解析: $url"
    
    try {
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"

        foreach ($line in $lines) {
            $line = $line.Trim()

            # 1. 直接越过基础空行说明和纯文本指导行 
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('!') -or $line.StartsWith('[')) {
                continue
            }

            # 2. 移除 DOM 与界面 UI 美化或修改元素的修饰字符规则以保护处理机制效能！
            if ($line -match '##|#\?#|\$\$') {
                continue
            }
            
            $domain = $null

            # 白名单 @@ 防伤检测解盔取用操作
            $isWhitelist = $line.StartsWith('@@')
            if ($isWhitelist) {
                $line = $line.Substring(2)
            }

            # 限定匹配如阻截像 image 或者 specific API, 我们提纯拦截根逻辑
            if ($line.Contains('$')) {
                $line = ($line -split '\$')[0]
            }

            # => 泛提取诸如标准 ||domain.xx 或 结合各种包含野生带 '*' 以及 dnsmasq IP等结构域名萃取逻辑 
            if ($line -match '^\|\|([a-zA-Z0-9*.-]+)\^?$') {
                $domain = $Matches[1]
            }
            elseif ($line -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }
            elseif ($line -match '^(?:address|server)=/([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})/') {
                $domain = $Matches[1]
            }
            elseif ($line -match '^([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }

            # 精密容错修复：将 .xxxx 之类的源病态提取规整或者丢包入防伤池！
            if (-not [string]::IsNullOrWhiteSpace($domain)) {
                
                # <核心修复点> 清除抓取解析后的残边余边无意义或语法误写引发开头带有多个"."与"-"点符号格式病态。
                # 会把 ".adverise.xx" => 转换重定向修复保存有效状态为 => "adverise.xx"，再靠外部检验来彻底洗去彻底脏了的东西。
                $domain = $domain.Trim().TrimStart('.').TrimEnd('.').TrimStart('-').TrimEnd('-')

                if ($isWhitelist) {
                    $excludedDomains.Add($domain) | Out-Null
                } else {
                    $uniqueRules.Add($domain) | Out-Null
                }
            }
        }
    }
    catch {
        Write-Host "处理链接出错[$url]: $_"
        Add-Content -Path $logFilePath -Value "处理错源 [$url]: $_"
    }
}

# --- 开始生成完美互通 Clash Meta 的安全验证处理清单排查 ---
$validRules =[System.Collections.Generic.HashSet[string]]::new()
$validExcludedDomains =[System.Collections.Generic.HashSet[string]]::new()

foreach ($domain in $uniqueRules) {
    if (Is-ValidRuleDomain($domain)) {
        $validRules.Add($domain) | Out-Null
    }
}
foreach ($domain in $excludedDomains) {
    if (Is-ValidRuleDomain($domain)) {
        $validExcludedDomains.Add($domain) | Out-Null
    }
}

# 终检:排开拦截被写入白名单里规避双相伤害防抵触！
$finalRules = $validRules | Where-Object { -not $validExcludedDomains.Contains($_) }

# Clash Meta 最底层解析转换逻辑结构分化保护：避免像 '.*.xxxx' 处理引发灾祸
$formattedRules = $finalRules | Sort-Object | ForEach-Object {
    if ($_ -match '\*') {
        "- '$_'"
    } else {
        "- '+.$_'"
    }
}

# 时间以及条项抓存反向数据提供统计结果：
$ruleCount = $finalRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 最后 Payload 集体编组输出:
$textContent = @"
# Title: AdBlock_Rule_For_Clash (Optimized Payload / Anti-Dot & Domain Syntax Cleaner Version)
# Description: 完美适用于Clash / Mihomo 的纯净高速防冲突阻断库集，智能排除 ".x.xxxx" 此类野生脏项防止解析链断裂。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# Generated on: $generationTime
# Successfully eliminated problematic ".x.xxx" format domain rules properly with Trim validations.
# Total valid effective filter rule counts : $ruleCount

payload:
$($formattedRules -join "`n")
"@

$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$textContent | Out-File -FilePath $outputPath -Encoding utf8

Write-Host "YAML核心层校验编译完全脱俗化过滤完成！剔出了异常.xxx结构引发的点崩溃！完全干净可用规则实体节点达：$ruleCount"
Add-Content -Path $logFilePath -Value "生成大顺 -> 排除清洗完成总成功载体规则节点计重达: $ruleCount"
