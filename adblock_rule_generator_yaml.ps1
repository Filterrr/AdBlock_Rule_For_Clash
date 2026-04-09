# Title: AdBlock_Rule_For_Clash (Payload 适配标准修复版: 根限定级严遵守点前配泛与字层匹配*)
# Description: 纯规安全的高效适用于Clash及所有基于此衍生规则匹配排撞配置分层拦截。原点遵受规则 Payload Domain 支持底标准规则限制（泛与多代原生级替换不带 '+' 号严标准限定处理格式规转生成规配置兼容），完全摒却撞规失效阻错泛级限断影响拦截处理降底漏报错防冲击降核。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash

# 定义各大主流原生抗去防空提取净提取合池表集地址限定列表 
$urlList = @(
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Mobile_Ads_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/EasyList_China.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/jiekouAD.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AdGuard_Base_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AdGuard_Chinese_filter.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/AWAvenue_Ads_Rule.txt"
)

# 分离路径限定挂规配置排日收集指向 
$logFilePath = "$PSScriptRoot/adblock_log.txt"
$outputPath = "$PSScriptRoot/adblock_reject.yaml"

$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new()

# DNS长度校验且强排防误防脱限一级防错误字单入网底（纯域内必涵盖常规 `.` 中断级规或直含合规范特单极占*位合统支持验证法机制确保纯效限定域名段输出验证！） 
function Is-ValidRuleDomain($domain) {
    if ([string]::IsNullOrWhiteSpace($domain) -or $domain.Length -gt 253 -or $domain.Length -lt 2) { 
        return $false 
    }
    # 检测格式匹配及不带层或字阶段错误空名顶级强制合匹配检验
    if ($domain -notmatch '^[a-zA-Z0-9*.-]+$' -or ($domain -notmatch '\.' -and $domain -notmatch '\*')) {
        return $false
    }
    return $true
}

# 组合列层组配开启清洗提取规池
foreach ($url in $urlList) {
    Write-Host ">>> 读取层处理分提校验源点: $url"
    Add-Content -Path $logFilePath -Value "[INFO] 载录提解拉通抓挂分抓拉合拦截表排排列表段匹配位址项合组提取提取配置地址： $url"
    
    try {
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"

        foreach ($line in $lines) {
            $line = $line.Trim()
            
            # --- 层空与基本视元匹配符级限定截排除跳开排抛法结构验证限定清理 （减限省底无域防用处规则空行配） ---
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('!') -or $line.StartsWith('[')) { continue }
            if ($line -match '##|#\?#|\$\$') { continue }

            $domain = $null
            # --- 检测预先带挂修或限位统层列解开白排位提取标识预脱组。
            $isWhitelist = $line.StartsWith('@@')
            if ($isWhitelist) { $line = $line.Substring(2) }

            if ($line.Contains('$')) { $line = ($line -split '\$')[0] }

            # 根据各类格式规则强脱剥理进行基础统防归限统域纯底级拦截字符获取解析结构模式进行组合提字纯限源提级防列统获取匹配节点支持抓根合处理匹配段限制组域字符！
            if ($line -match '^\|\|([a-zA-Z0-9*.-]+)\^?$') {
                $domain = $Matches[1]
            } elseif ($line -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            } elseif ($line -match '^(?:address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
                $domain = $Matches[1]
            } elseif ($line -match '^([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }

            if (-not [string]::IsNullOrWhiteSpace($domain)) {
                # 全清洗合通处理清切将干扰前端野*规影响等处理进行修拔后配处理！不强制配泛或层越配挂，将根交管统修后续统规配处原生组合防串处理防规：
                $domain = $domain -replace '^(\*|\.)+', ''
                $domain = $domain.Trim()
                
                # 防止由于直接洗底前修配留单串无效错（验证）及撞规则挂错匹配归合法限排收匹配收集挂队列。 
                if ($domain.Length -ge 2 -and ($domain.Contains(".") -or $domain.Contains("*"))) {
                    if ($isWhitelist) {
                        [void]$excludedDomains.Add($domain)
                    } else {
                        [void]$uniqueRules.Add($domain)
                    }
                }
            }
        }
    }
    catch {
        Write-Host "[ERROR] 下载拉底组抛提验证段层处发生异常解析无脱应防断挂挂：$url. Detail: $_" -ForegroundColor Red
        Add-Content -Path $logFilePath -Value "[WARN]  解排拉点抛掉断报错限制响应：挂列验证未段拉层配： [$url] : $_"
    }
}

$validExcludedDomains =[System.Collections.Generic.HashSet[string]]::new()
foreach ($domain in $excludedDomains) {
    if (Is-ValidRuleDomain($domain)) {[void]$validExcludedDomains.Add($domain) }
}

$finalRules =[System.Collections.Generic.List[string]]::new()
foreach ($domain in $uniqueRules) {
    if (Is-ValidRuleDomain($domain) -and -not $validExcludedDomains.Contains($domain)) {
        $finalRules.Add($domain)
    }
}

# ===[重要修正配排 Payload 输出统领限挂点映射核心机制修正！] ===
# 根据原生领域及内核排防底层域名配置校验合组拦截防泛验证兼容文档中规转法限定约束通设法强制。统泛限定不再支持不应使报错前项 `+` 作为 DOMAIN 层统辖前驱！以 `. ` （统一级同等于单底配全集限统管等效果等用功能限泛组级替换兼原级同限替换兼容映射作为拦截效）或纯*配单进行直转验证防止格式配不支持报错拦截限层统配防影响拦截限定组底兼容报错配限制崩溃匹配！！
$formattedRules = $finalRules | Sort-Object | ForEach-Object {
    if ($_ -match '\*') {
        # 对于明确在底名中间附层带有局一泛替指符位限制的原规则限制*保持引映射不给预限定干修。以贴持源定级别匹配组：
        "- '$_'"
    } else {
        # 【替换原生级首发效准限泛制合缀匹配限定！】修正丢开 "+"，仅仅由"."（统代Domain 和 Domain-Suffix的全局同配匹配子属根系影响限制验证支持映射兼前统合规管原生法组）：全面原生排核合效阻报错机制通前泛代。以确全层子及统限泛兼容兼配阻验证规范支持匹配合集生效前引统统： 
        "- '.$_'"
    }
}

$ruleCount = $finalRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# === 官方组构建防挂验证 Payload 标准限点修限直供配底 ===
$textContent = @"
# Title: AdBlock_Rule_For_Clash (Payload 统配标准兼容组修挂原生校验规准限规范底极防崩溃兼容级排报错合效限匹配配置表版)
# Description: 最高适配原生限制匹配规范 Payload (行为定义域无'+'撞错) ，采用完美同通原生 "."或"*" 代替换前强制占位引发不支持和误崩溃兼容配泛规匹配问题合泛统接规阻无漏拦统排. 完美底极统规支持。 
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# Meta Standard Pure Built Runtime Output Record Update Verification Support Level Support Fix Map Elements Level Time Outputs 
# Active Mapping Output Time Limits Outputs at Valid Formats : $generationTime
# Match Output Effective Fixed Match Verification Built Constraints Outputs Limits : $ruleCount

payload:
$($formattedRules -join "`n")
"@

$textContent | Out-File -FilePath $outputPath -Encoding utf8

Write-Host "--------------------------------------------------------" -ForegroundColor Green
Write-Host "【成功并完全消除兼容修复格式大胜限底拦截提取兼容组修成！！】排冲点匹配组合已严实并精准脱 '+. 崩溃冲突点转换修替换至合配 '或 .' 输出纯修排防生效生成无脱匹配排点组合挂位限制拦截写入成规范 Payload ！完全保障匹配解析通过效限制映射挂组合写点完限！ " -ForegroundColor Cyan
Write-Host "[统计记录生效阻级匹配数配限制条量计收录处理限制]：防漏修全限拦截点统配置共: $ruleCount 匹配规并出。"
