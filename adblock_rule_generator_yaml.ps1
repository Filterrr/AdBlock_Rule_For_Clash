# Title: AdBlock_Rule_For_Clash (Optimized Version)
# Description: 适用于 Clash / Meta 原生模式过滤拦截域名规则集，已优化增强排雷策略，规避伪泛域名(如*.com)、形似短域名(如 x.xxx) 及静态文件扩展(如 *.js) 所引起的误杀、防阻 Clash 网关核平与内存爆炸等风险。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash

# ----------------- 1. 配置部分 -----------------

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

# 确保脚本当前所在目录上下文准确性
$currentPath = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($currentPath)) {
    $currentPath = (Get-Location).Path
}

# 预设各种产出与输出记录点配置路径
$logFilePath = "$currentPath/adblock_log.txt"
$outputPath  = "$currentPath/adblock_reject.yaml"

# 初始化环境反馈以及开启空清空缓存的日志
"Start Execution Time: $((Get-Date).ToString())" | Out-File -FilePath $logFilePath -Encoding utf8

# ----------------- 2. 工具和函数部分 -----------------

# 统一创建 WebClient 获取资源对象并伪装 Header 以增加下行安全性与成功率
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

# 定义两个集合收集：拦截主列表 和 排错白名单防碰瓷
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains =[System.Collections.Generic.HashSet[string]]::new()

# DNS格式和拦截字符串防沉淀检验增强
function Is-ValidRuleDomain($domain) {
    # 1. 常规容错和超长/超短越界基础判断
    if ([string]::IsNullOrWhiteSpace($domain) -or $domain.Length -gt 253 -or $domain.Length -lt 3) { 
        return $false 
    }
    
    # 2. 安全性核验：让含有合法泛匹配统配符的合法格式(星号*)、通用中划横线、常规域名能平滑纳入 Meta
    if ($domain -notmatch '^[a-zA-Z0-9*.-]+$') {
        return $false
    }
    
    # ---------------- 优化过滤 "x.xxx" / 野生坑点格式 ----------------
    
    # 3. [核心拦截]: 单一占位结构形式阻断 (诸如 x.com, a.cn, *.com，t.co 等)
    # 防止大范围误杀重要业务和通配根服务器而致使整体翻车核平现象
    if ($domain -match '^[a-zA-Z0-9*]\.[a-zA-Z]+$') {
        return $false
    }
    
    # 4. [辅助加强]: 拓展防沉淀干扰假域名阻隔机制过滤扩展。
    # 识别防止形如如 ad.js / bg.jpg 等假域化产物写入污染系统，保持 Clash 的 Payload 精细纯净健康工作：
    if ($domain -match '(?i)\.(png|jpg|jpeg|gif|ico|bmp|svg|mp3|mp4|avi|swf|css|js|txt|php|html|woff|woff2|ttf)$') {
        return $false
    }
    
    return $true
}

# ----------------- 3. 网络抓取和语法解析 -----------------

# 遍历地址开启分析与精妙转接提取
foreach ($url in $urlList) {
    Write-Host "正在拉取解析处理源集: $url" -ForegroundColor Cyan
    Add-Content -Path $logFilePath -Value "正在解析: $url"
    
    try {
        # 下载配置以文本获取数据
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"

        foreach ($line in $lines) {
            $line = $line.Trim()

            # --- Adblock语法抛弃规则 ---
            # 1. 直接越过基础空行说明和纯文本指导行 （开头 ！或[ 开头即Meta信息等）
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('!') -or $line.StartsWith('[')) {
                continue
            }

            # 2. `##`, `#?#`, `$$` 等CSS渲染端页面排版屏蔽机制效应剔除空间缩略容纳精简分析。
            if ($line -match '##|#\?#|\$\$') {
                continue
            }
            
            # --- Adblock语法逻辑转化匹配预加工 ---
            $domain = $null

            # `@@` - 检测代表免流/放入避撞排雷护盾隔离保释免罪网名单中白化。
            $isWhitelist = $line.StartsWith('@@')
            if ($isWhitelist) {
                $line = $line.Substring(2)
            }

            # 修饰符 `$` 阻断拆除截后抛除法剥除多重网层标识影响。
            if ($line.Contains('$')) {
                $line = ($line -split '\$')[0]
            }

            # 解析常用标准地址分发的各种核心字符串捕获结构匹配策略模式:
            # => 标准AdBlock域名形式 `||domain.xxx^` (涵盖 '*') -> Clash最标准。
            if ($line -match '^\|\|([a-zA-Z0-9*.-]+)\^?$') {
                $domain = $Matches[1]
            }
            # => Hosts拦截形式映射机制拦截获取支持剥离
            elseif ($line -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }
            # => DNSmasq过滤格式屏蔽分离捕获防流窜获取机制直调抓源支持萃取。
            elseif ($line -match '^(?:address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
                $domain = $Matches[1]
            }
            # => 标准素颜纯文本普通提取长宽高字拦截域长结构附和匹配验证包含可能附合 (*)：
            elseif ($line -match '^([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})$') {
                $domain = $Matches[1]
            }

            # 处理落网者提取录制名单编内归收整合系统
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
        Write-Host "处理链接出错[$url]: $_" -ForegroundColor Red
        Add-Content -Path $logFilePath -Value "处理错源 [$url]: $_"
    }
}

# ----------------- 4. 安全二次效验净化编译整合产物组出包 -----------------
Write-Host "资源合并下线结束，进行 Payload Clash 内核适应标准化清洗提速防撞击与除脏..." -ForegroundColor Yellow

$validRules = [System.Collections.Generic.HashSet[string]]::new()
$validExcludedDomains =[System.Collections.Generic.HashSet[string]]::new()

# 第一层效力与星源规则格式校验与除死阻机制
foreach ($domain in $uniqueRules) {
    if (Is-ValidRuleDomain($domain)) {
        $validRules.Add($domain) | Out-Null
    }
}

# 第二层进行验证对冲保障规护护免规则拦截列处理白屏拦截列名单清算核。
foreach ($domain in $excludedDomains) {
    if (Is-ValidRuleDomain($domain)) {
        $validExcludedDomains.Add($domain) | Out-Null
    }
}

# 通过逻辑碰撞减负系统求并除反提取剔去冲突条项排障
$finalRules = $validRules | Where-Object { -not $validExcludedDomains.Contains($_) }

# Clash / Meta 标准直连 Payload 无痛转换机制兼容映射转换构建：
# 将安全拦截提取直接化兼容转化格式: "支持*带容错转直" "以及不支持常规以+添加包含网层涵盖阻隔网络"。
$formattedRules = $finalRules | Sort-Object | ForEach-Object {
    if ($_ -match '\*') {
        "- '$_'"
    } else {
        "- '+.$_'"
    }
}

$ruleCount = $finalRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 最后 Payload 安全成列块化文档导出整合文本写入构建层架构 YAML:
$textContent = @"
# Title: AdBlock_Rule_For_Clash (Optimized with Mihomo standard handling payload logic)
# Description: 完美适用于Clash / Mihomo 的纯净高速版防冲规则, 原生兼容支持 Adblock 修饰筛选。支持野生抗雷与假域除垢净化处理优化加速引擎支持效验网络降报错阻力版。
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# Generated on: $generationTime
# Generated valid domains Payload block outputs safely!
# Total efficient filter matching items payload nodes: $ruleCount

payload:
$($formattedRules -join "`n")
"@

$textContent | Out-File -FilePath $outputPath -Encoding utf8

Write-Host "===============================" -ForegroundColor Green
Write-Host "处理和生成构建已经成功跑完全程工作链任务！" -ForegroundColor Green
Write-Host "=> 规则库拦截精粹后总规模：$ruleCount"
Write-Host "=> 安全存储导出点已存放至: $outputPath"
Write-Host "===============================" -ForegroundColor Green

Add-Content -Path $logFilePath -Value "====== 自动化打包整合系统大工作已全部按质高效执行结束产生成落！=> 汇融精准规限去粗取存规则拦截计数结果核: $ruleCount"
