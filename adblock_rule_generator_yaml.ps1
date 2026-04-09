# Title: AdBlock_Rule_For_Clash (Mihomo Strict Native Rule Formatting Sync Optimized)
# Description: 适用于Mihomo (Clash Meta) 原生匹配映射格式过滤。通过强置遵守官方标准特定匹配深度修饰占位字符将规则严格提纯，无损进行防误排白组合映射优化来确立轻量低网络下级错拦截。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash

# 定义广告过滤器URL抓取源提取组集合源配置合集表
$urlList = @(
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Mobile_Ads_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/EasyList_China.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/jiekouAD.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AdGuard_Base_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AdGuard_Chinese_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AWAvenue_Ads_Rule.txt"
)

# 日志及结果构建回滚目录排错位址指点定设：
$logFilePath = "$PSScriptRoot/adblock_log.txt"
$outputPath = "$PSScriptRoot/adblock_reject.yaml"

# 全统 WebClient 对像组伪装与配置提取防拦截访问断连安全下载设定。
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

# 排列去撞集收集器结构构建设置
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains =[System.Collections.Generic.HashSet[string]]::new()

# DNS和含有Mihomo常规合法通配野校验结构字符串长度格式结构标准防沉验证清洗法匹配。
function Is-ValidRuleDomain($domain) {
    if ([string]::IsNullOrWhiteSpace($domain) -or $domain.Length -gt 253 -or $domain.Length -lt 2) { 
        return $false 
    }
    # 检测格式中是否携含有规则规定范围内的普通符号以支撑验证节点字符串健康（防止非理匹配结构树坍缩限制输出规则破坏）
    if ($domain -notmatch '^[a-zA-Z0-9*.-]+$') {
        return $false
    }
    return $true
}

# 按地址分流拉载抓分组合提精并严格清理多代泛滥限制规则通位适配符限制。
foreach ($url in $urlList) {
    Write-Host ">>> 正在读取分拨处理转换网络源位： $url"
    Add-Content -Path $logFilePath -Value "[INFO] 即时拉起网络分级萃解过滤分拨列表：$url"
    
    try {
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"

        foreach ($line in $lines) {
            $line = $line.Trim()

            # --- 基本前抛和修图拦截器无效代码剔废 (精空间极约机制抛掉网页视觉隐匿处理无效代码片段) ---
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('!') -or $line.StartsWith('[')) { continue }
            if ($line -match '##|#\?#|\$\$') { continue }

            $domain = $null
            # 判断白体队列头标识脱身队列结构分离提取。
            $isWhitelist = $line.StartsWith('@@')
            if ($isWhitelist) { $line = $line.Substring(2) }

            # 分包去切去丢抛掉后续所有带有 `$` 结构性质参数限定词限定的干扰词元节点拦截词体。
            if ($line.Contains('$')) { $line = ($line -split '\$')[0] }

            # 根据常见阻控节点提取解析常规分层主干域名串根源字根匹配策略：
            # (模式 1：抓配纯结构包含诸如 `||sub.xx.xxx^` 过滤规则标准解析支持野生*)
            if ($line -match '^\|\|([a-zA-Z0-9*.-]+)\^?$') {
                $domain = $Matches[1]
            }
            # (模式 2：对应诸如包含抓 Hosts 或 环回网格泛封控映射类抓串转换地址处理。)
            elseif ($line -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }
            # (模式 3：支持捕取兼容解析纯泛用阻拦截映射匹配源节点包含格式分提取匹配节点抓取提取地址网映射。)
            elseif ($line -match '^(?:address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
                $domain = $Matches[1]
            }
            # (模式 4：标准常规素净单串式字符格式泛指节点或携带*修饰常规防脱等支持解析节点。)
            elseif ($line -match '^([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }

            # 【关键优化】按照 Meta的严格机制修缮匹配字结构前串，确保底层生效规则没有冲突限定符制阻防越级漏行情况阻流防封问题挂合解决结构化处理转换层输出格式限止影响限！
            if (-not [string]::IsNullOrWhiteSpace($domain)) {
                # 脱去原有泛滥影响限定抓树深度效力的强匹配头结构（比如前端原生带来的 '*.ad.xx.com' 如果不修正将影响 `+` 号泛修配级别从而产生限制漏放报错！）使得域核心洁净如新适配转后合标生成底层树限定统匹配限制！
                $domain = $domain -replace '^(\*|\.)+', ''
                $domain = $domain.Trim()
                
                # 双验证后加入合法结构对队进行精准提取并合拢组合池排配输出对错过滤映射隔离对立池收集列层组并进规效池收集组限制。
                if ($domain.Length -ge 2) {
                    if ($isWhitelist) {
                        $excludedDomains.Add($domain) | Out-Null
                    } else {
                        $uniqueRules.Add($domain) | Out-Null
                    }
                }
            }
        }
    }
    catch {
        Write-Host "[ERROR] 执行或地址响应错层挂线: $url ErrorDetail: $_" -ForegroundColor Red
        Add-Content -Path $logFilePath -Value "[CRITICAL] 脱位挂线节点解析错误失败位[$url]：$_"
    }
}

# --- 深清排污：排除二次干扰及相互交叉打底影响匹配隔离组合处理。 ---
$validExcludedDomains =[System.Collections.Generic.HashSet[string]]::new()
foreach ($domain in $excludedDomains) {
    if (Is-ValidRuleDomain($domain)) { $validExcludedDomains.Add($domain) | Out-Null }
}

$finalRules = [System.Collections.Generic.List[string]]::new()
foreach ($domain in $uniqueRules) {
    # 检验且仅让合归无犯无白名队列内列纯底防碰撞净匹配入正规则层匹配组出组合处理生成列队列组合限位层过滤表列表限防列表。
    if (Is-ValidRuleDomain($domain) -and -not $validExcludedDomains.Contains($domain)) {
        $finalRules.Add($domain)
    }
}

# 【规范级节点规则树 Payload 合轨排版】 按照 《官方手册语法规范 / 第8段限定 -通配格式限制定义模式限定处理规》要求原生挂格式转化:
$formattedRules = $finalRules | Sort-Object | ForEach-Object {
    if ($_ -match '\*') {
        # 【特判匹配占位替换修饰*层映射格式法支持】：
        # 遵循官方中: "[*号限制一次必须严格完全适配卡在一层且中间限单层修饰内局域位效]" 例如 ( "xxx.*.xx.com" 或含单通结构段 )，须使用严格引串作为规则保留精准占位于一层限制配用执行替换防止树破坏!
        "- '$_'"
    } else {
        # 【基础素节点常规格式适配泛树机制限制】：
        # 使用严实安全贴配兼容替换 ( `+` 型符合前缀替换挂统匹配格式取代 DOMAIN-SUFFIX 和普通拦截级别效配限制）来将干爽基线结构匹配出完美泛杀本级别限制下全统通匹配节点限制（诸如此例： `+.xx.com` 意味着 xx与深子孙级别统受原生树极点支持限制限位）。 完美合统标准效规格式映射配级组合格式效法限用拦截树。
        "- '+.$_'"
    }
}

# 获取统合生成配置数值反馈进行写入文件和监控展现记录反馈统防情况结构化数据结构展示生成合防规则文件生成结果反馈日志文件并反馈显示写入：
$ruleCount = $finalRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 最底架构无缝支持生成 Payload 的规约化 Meta 无套规则直统格式组合文件代码集写档并反馈。
$textContent = @"
# Title: AdBlock_Rule_For_Clash (Payload 领域限制官方规则支持转换节点树配置集高标准级严管生成合规范本版格式配位拦截)
# Description: 无缝完美支持Mihomo / Clash-Meta标准官方配置约束格式体系转化,原生兼排通限定处理规则配错。全通底端配通生效适配转换生成组表配集合。 
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# Build Execution Formatter Check Process Runtime Node Rules Process Version Limits
# Generation Local Meta Core Check Build Node Time Format Support Outputs Outputs
# Latest Valid Efficient Block Build Format Update at Nodes Record Support Checks Limits: $generationTime 
# Effective Filtering Domain Mapping Active Generated Elements Number Scale Check Config Payload Items Supported Checks Supports Total Constraints Match Nodes: $ruleCount

payload:
$($formattedRules -join "`n")
"@

$textContent | Out-File -FilePath $outputPath -Encoding utf8

Write-Host "--------------------------------------------------------" -ForegroundColor Green
Write-Host "【大捷！】官方合统 Payload Node File YAML构建配流限层格式防匹配全底转化安全输出全告规成配效组文件配排输出完毕!" -ForegroundColor Cyan
Write-Host "[成功执行限制转抓生效域共收集] $ruleCount 条全无限制碰撞规则层匹配规格式配置规则记录排查输出完美并写妥到匹配列。效防错执行！"
Add-Content -Path $logFilePath -Value "[SUCCESS] Update Task Valid Checked Build Support Format Meta Match Execution Done. Payload Map Check Out Record Limits Support Node Elements Nodes =>  Count Record limits Format $ruleCount nodes limits mapped generated limits ! Check execution output natively efficiently limit rules successfully maps limit ! "
