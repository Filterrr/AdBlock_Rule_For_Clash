# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，按Clash-Meta原生模式过滤CSS以及兼容各标识匹配符号拦截，确保即时同步上游且将白名单映射降低网络直联层误杀。
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
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new()

# DNS格式和拦截字符串防沉淀检验增强，让星号('*')得以通入匹配以接纳野外模式下的域名覆盖策略。
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

            # --- Adblock语法抛弃规则 ---
            # 1. 直接越过基础空行说明和纯文本指导行 （开头 ！或 [ 开头即Meta信息等）
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('!') -or $line.StartsWith('[')) {
                continue
            }

            # 2. `##`, `#?#`, `$$` 等CSS渲染端页面排版或DOM修改隐匿屏蔽元素由于网络抓取无任何实际DNS底层分发限制逻辑效应。直接暴力排除屏蔽以求精简解析空间！
            if ($line -match '##|#\?#|\$\$') {
                continue
            }
            
            # --- Adblock语法逻辑转化匹配预加工 ---
            $domain = $null

            # `@@` - 检测如果前头开头代表免流 / 本规则应当无损放入避撞击排白队列
            $isWhitelist = $line.StartsWith('@@')
            if ($isWhitelist) {
                # 解掉头盔标志开始读取其后面的匹配身板
                $line = $line.Substring(2)
            }

            # 修饰符 `$` 阻断限定过滤拆封机制 （像$image , $third-party 这些限定行为我们仅仅摘其上层大区域进行直接整包限制过滤即可发挥网络分层的拦截效能。）
            if ($line.Contains('$')) {
                $line = ($line -split '\$')[0]
            }

            # 解析常用标准地址分发的各种核心字符串捕获结构匹配策略模式:
            # => 支持标准AdBlock域名及下延屏蔽 `||domain.xxx^` (兼具野生含*号) -> Clash原生认此。
            if ($line -match '^\|\|([a-zA-Z0-9*.-]+)\^?$') {
                $domain = $Matches[1]
            }
            # => Hosts形式 (支持诸如0.0.0.0或含有IPv6拦截等模式格式结构地址映射支持转换拦截 )
            elseif ($line -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }
            # => 识别dnsmasq格式拦截列表直接萃取
            elseif ($line -match '^(?:address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
                $domain = $Matches[1]
            }
            # => 标准无杂念素面字符长宽行域名形式（涵盖可能的匹配附着模式例如 *)
            elseif ($line -match '^([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }

            # 分别添加落网或者进入保释白名单组的精炼防呆剔出过滤！
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

# --- 开始生成完美互通 Clash Meta 的安全验证处理清单排查 ---
$validRules = [System.Collections.Generic.HashSet[string]]::new()
$validExcludedDomains =[System.Collections.Generic.HashSet[string]]::new()

# DNS和含有正规'*'野生占位校验符规范二次校准清洗筛取
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

# 依据双排防相冲白条规准则排遣拦截规则列以达成更无脑高效降报错的拦截体系组合
$finalRules = $validRules | Where-Object { -not $validExcludedDomains.Contains($_) }

# Clash Meta 最底层解析输出结构化兼容转换格式:
# 若其中因为AdBlock提取具有野性的含有任意长度标识 "*" 进行通配域支持的话直接输出现字元以防解析报错崩溃（支持部分Meta核进行内置星号Regex配适，也可适配泛领域字符串模式）
# 而传统通用无星规则强制添加以 "+.domain.com" 来兼容通配一切子级的顶级网络全限制。
$formattedRules = $finalRules | Sort-Object | ForEach-Object {
    if ($_ -match '\*') {
        "- '$_'"
    } else {
        "- '+.$_'"
    }
}

# 构建基本环境验证反馈展示
$ruleCount = $finalRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 最后生成供 YAML Meta 使用标准的兼容有效行为纯粹 Payload 文档：
$textContent = @"
# Title: AdBlock_Rule_For_Clash (Optimized with Mihomo standard handling payload logic)
# Description: 完美适用于Clash / Mihomo 的纯净高速版防冲规则, 原生兼容支持 Adblock 修饰筛选。每20分钟即时处理。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# Generated on: $generationTime
# Generated valid domains Payload block outputs safely!
# Total efficient filter matching items payload nodes: $ruleCount

payload:
$($formattedRules -join "`n")
"@

$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$textContent | Out-File -FilePath $outputPath -Encoding utf8

Write-Host "拦截 Payload Yaml 输出编译大功告成！完美精炼总提取数额规则：$ruleCount"
Add-Content -Path $logFilePath -Value "更新完成 -> Total efficient mapping valid entities count limits: $ruleCount"
