# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，按Clash-Meta原生模式过滤CSS以及兼容各标识匹配符号拦截，确保即时同步上游且将白名单映射降低网络直联层误杀。带有增强一级域名域泛匹配免冲保释排查逻辑！
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash

# ========================================
# ======= ★[自定义:防污染规则排误名单配置] =======
# ========================================
# 功能: 把你需要全通通行保证正常可用性或者防范外部强控大额封锁的主营根域添加至此处(仅需填写无前缀的裸结构即可):
$customRootWhitelist = @(
    "youtube.com",       # 您所要求指定例外的核心根基防杀级域。包括如 +.youtube.com 以及广告拦截包内一切其同构延伸子请求的拉入名单都将被丢掉屏蔽记录。
    "googlesyndication.com" # 作为格式样板，其它自定义都可以同格式无限增加（如需删除把行抹掉即可）
)

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
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new()

# DNS格式和拦截字符串防沉淀检验增强
function Is-ValidRuleDomain($domain) {
    if ([string]::IsNullOrWhiteSpace($domain) -or $domain.Length -gt 253 -or $domain.Length -lt 2) { 
        return $false 
    }
    # 让含有合法泛匹配统配符的合法格式(星号*)、通用中划横线、常规域名能平滑纳入 Meta 野生环境进行生效计算。
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

            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('!') -or $line.StartsWith('[')) {
                continue
            }

            if ($line -match '##|#\?#|\$\$') {
                continue
            }
            
            $domain = $null

            # `@@` 为白名单开头机制标记识别 
            $isWhitelist = $line.StartsWith('@@')
            if ($isWhitelist) {
                $line = $line.Substring(2)
            }

            if ($line.Contains('$')) {
                $line = ($line -split '\$')[0]
            }

            if ($line -match '^\|\|([a-zA-Z0-9*.-]+)\^?$') {
                $domain = $Matches[1]
            }
            elseif ($line -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }
            elseif ($line -match '^(?:address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
                $domain = $Matches[1]
            }
            elseif ($line -match '^([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }

            if (-not [string]::IsNullOrWhiteSpace($domain)) {
                $domain = $domain.Trim()
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

# 建立核心合法的干净池塘以防错误杂兵符号渗透干扰构建引擎运转。
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


# =====================★ 高度匹配剔除算法环节配置引擎优化  =============================
# 先从自定义列表中智能预先编译后缀高防匹配安全正则表达式：用做在十万级库当中做到超神级性能免碰撞甄查脱逃 （Domain Suffix）模式匹配支持： 涵盖该域 + 本身任何所有携带从上而落节点的保护验证判定!
$bypassRegexPattern = ""
if ($customRootWhitelist.Count -gt 0) {
    # 编织组成了极其极速强大的过滤正规算式表达式 例如：  ^(?:.*\.)?(youtube\.com|google\.com)$ ；从而仅在保证合法结尾的主次根基的匹配下对列表记录作出脱水
    $bypassRegexPattern = "^(?:.*\.)?(" + (($customRootWhitelist | ForEach-Object { [regex]::Escape($_) }) -join "|") + ")$"
}

# 高清化解排除过滤生成纯净体系以避免自冲式直降撞车的最终规约
$finalRules = $validRules | Where-Object { 
    $inspectHost = $_
    
    # 【白区层验A】 首先判断是否是在内置标准Ad-Filter库解析语法规范里 `@@`  带下的免查豁出队列里拥有豁权证明 ：
    if ($validExcludedDomains.Contains($inspectHost)) {
         return $false  # 返回为 False 并拦截剔去入Payload的入池动作 
    }
    
    # 【白区层验B】 判断匹配本轮中您定义或附着的自定制保权主顶级安全释放域阵内所牵引涵盖的部分 (涵盖后缀免验体系)： 只要您列写了一级主体 `xxx.yyy`, 下面带的所有诸如被上源不小心收列到的阻拦名单节点全全舍废退换放路直接全通通行 ！
    if (-not [string]::IsNullOrEmpty($bypassRegexPattern) -and ($inspectHost -match $bypassRegexPattern)) {
        return $false   # 即该列拦截源直接因为存在或隶属于保护网中宣告豁免移除保护剔除了！不做屏蔽录入。
    }
    
    # 均不命中的被确断定型实实在在流氓或者危险或不合理广告点的话我们一揽通收入规正册保留输出进行Clash底层过滤处决
    return $true
}

# 输出构建规范机制 ：根据是否存在模糊带星号结构作自动化的安全保护式补码拼接
$formattedRules = $finalRules | Sort-Object | ForEach-Object {
    if ($_ -match '\*') {
        "- '$_'"
    } else {
        "- '+.$_'"
    }
}

# 环境运算反馈并展示打印工作时长标贴印记：
$ruleCount = $finalRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# Clash Meta 最后生长的适配 YAML 无误净速阻遏过滤列表节点档构建结构树成卷 ：
$textContent = @"
# Title: AdBlock_Rule_For_Clash (Optimized & Self-Exempt Logic Enhanced Payload mode Edition)
# Description: 适用于 Clash / Mihomo / Meta 标准版，拥有用户根底层级防护免防直白域名的独立屏蔽机制，大幅降低直接业务根误封风险能力的安全特快处理版本。 
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# Generate time zone (+8.Beijing Area Synchronized Clocking Time Zone) Record Mark : $generationTime
# Payload List Contains Overall Ad Tracking Domains Elements: $ruleCount Entities Injected Successfully! 

payload:
$($formattedRules -join "`n")
"@

$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$textContent | Out-File -FilePath $outputPath -Encoding utf8

Write-Host "YAML 清理白名单过滤屏蔽重合项构建逻辑结束、合并优化重列及打包完毕。总拦截净生效核心负载计数是: $ruleCount 宗!"
Add-Content -Path $logFilePath -Value "Ad-Core Refreshments Routine successfully ended and compiled clean mapping valid payload entries entity scale nodes quantity sum values bounded down:  $ruleCount."
