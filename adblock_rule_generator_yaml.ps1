# Title: AdBlock_Rule_For_Clash
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0

# 定义广告过滤器URL列表
$urlList = @(
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "https://raw.githubusercontent.com/Filterrr/AdBlock_Rule_For_Clash/main/allowlist.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt"
)

# 日志文件路径
$logFilePath = "$PSScriptRoot/adblock_log.txt"
Clear-Content -Path $logFilePath -ErrorAction SilentlyContinue

# 日志输出函数
function Write-Log($message) {
    Write-Host $message
    Add-Content -Path $logFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
}

Write-Log "开始更新并转换广告拦截规则..."

# 创建 HashSet 来存储唯一的规则和排除的域名，使用 OrdinalIgnoreCase 忽略大小写，极大提高查找效率
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# 创建 WebClient 对象用于下载规则
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
$webClient.Encoding = [System.Text.Encoding]::UTF8

# 预编译正则表达式以提升性能
# 匹配标准域名的正则 (符合 RFC 规范)
$domainRegex = '^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$'

foreach ($url in $urlList) {
    Write-Log "正在拉取并处理: $url"
    try {
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"

        foreach ($line in $lines) {
            $line = $line.Trim()

            # 快速跳过空行和各类注释行
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("!") -or $line.StartsWith("#") -or $line.StartsWith("[")) {
                continue
            }

            $domain = $null
            $isWhitelist = $line.StartsWith("@@")

            if ($isWhitelist) {
                $line = $line.Substring(2)
            }

            # 1. 匹配 Adblock/Easylist 格式
            if ($line -match '^\|\|([a-zA-Z0-9.-]+)(?:\^|$)') {
                $domain = $Matches[1]
            }
            # 2. 匹配 Hosts 格式
            elseif ($line -match '^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+)') {
                $domain = $Matches[1]
            }
            # 3. 匹配 Dnsmasq 格式
            elseif ($line -match '^(?:address|server)=/([a-zA-Z0-9.-]+)/') {
                $domain = $Matches[1]
            }
            # 4. 匹配纯域名格式
            elseif ($line -match '^([a-zA-Z0-9.-]+)$') {
                $domain = $Matches[1]
            }
            # 5. Surge/Clash规则: DOMAIN-SUFFIX,example.com
            elseif ($line -match '^DOMAIN(?:-SUFFIX)?,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})') {
                $domain = $Matches[1]
            }

            # 验证域名合法性并加入对应集合
            if ($domain -and $domain -match $domainRegex) {
                if ($isWhitelist) {
                    $excludedDomains.Add($domain) | Out-Null
                } else {
                    $uniqueRules.Add($domain) | Out-Null
                }
            }
        }
    }
    catch {
        Write-Log "处理 $url 时出错: $_"
    }
}

Write-Log "规则拉取完成。总计提取域名: $($uniqueRules.Count) 个，白名单域名: $($excludedDomains.Count) 个。"
Write-Log "正在进行冗余子域名清理优化 (提升 Clash 解析性能)..."

# 临时储存已剥去多余子级子域名的优化合集
$tempOptimized = [System.Collections.Generic.List[string]]::new()

foreach ($domain in $uniqueRules) {
    # 排除白名单域名
    if ($excludedDomains.Contains($domain)) {
        continue
    }

    $parts = $domain -split '\.'
    $isRedundant = $false

    if ($parts.Length -gt 2) {
        for ($i = 1; $i -lt ($parts.Length - 1); $i++) {
            $parentDomain = ($parts[$i..($parts.Length-1)]) -join '.'
            if ($uniqueRules.Contains($parentDomain) -and -not $excludedDomains.Contains($parentDomain)) {
                $isRedundant = $true
                break
            }
        }
    }

    if (-not $isRedundant) {
        $tempOptimized.Add($domain)
    }
}


Write-Log "正在进行高并发并行 DNS 存活有效验证... 总量：$($tempOptimized.Count) 个(淘汰解析失效与死域名)"

# 创建经过存活判定过关的核心集合
$optimizedRules = [System.Collections.Generic.List[string]]::new()

# DNS异步配置常量
$chunkSize = 200      # 并发线程批量（根据Github Action算力设定较大值可飞速消化上万请求，若您是在本地家用破烂路由器环境测设执行则建议缩窄该值为30以免瞬时挤爆NAT)
$timeoutMs = 1500     # 解析上限：超过1500毫秒强制挂起并踢掉死域名 (解决部分偏门广告网络完全无响应从而卡住流程数天)

for ($i = 0; $i -lt $tempOptimized.Count; $i += $chunkSize) {
    # 切割列表，防止溢出上界限
    $upperBound = [math]::Min($i + $chunkSize - 1, $tempOptimized.Count - 1)
    $chunk = $tempOptimized[$i..$upperBound]

    $taskDict = [ordered]@{}
    $taskList = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()

    # 高并发装入系统任务树
    foreach ($dom in $chunk) {
        try {
            # 发起到底层的后台 DNS 多维查询(返回一个状态追踪对象而不是锁死前台阻塞)
            $task = [System.Net.Dns]::GetHostAddressesAsync($dom)
            $taskDict[$dom] = $task
            $taskList.Add($task)
        }
        catch {}
    }

    $taskArray = $taskList.ToArray()
    if ($taskArray.Length -gt 0) {
        try {
            # 高性能：限时等待这组 200个解析 异步反馈完成；不达条件一到限制就立刻终止不浪费秒数！
            [void][System.Threading.Tasks.Task]::WaitAll($taskArray, $timeoutMs)
        } catch {
            # 内部任务报废（例如无效/不返回的脏域抛错给 WaitAll ）触发预料异常丢弃不干扰剩余对象执行。
        }
    }

    # 读取异步结束结果查阅这几百人的考试报告（不重新走网段验证，只看Task本身附带的状态即可辨活口）
    foreach ($dom in $taskDict.Keys) {
        $t = $taskDict[$dom]
        # 解析顺利拿到回溯记录 (没有在互联网被注册或停止分发的死亡域名必然因拿不到回报而爆异常触发 Task Status：Faulted 或 Cancelled)
        if ($t.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion) {
            $optimizedRules.Add($dom)
        }
    }
    
    # 给用户控制台或者服务器 Actions log 上提供缓解挂起焦虑的友好滚动进度反馈
    if ((($i + $chunkSize) % 2000) -lt $chunkSize) {
         Write-Log " -- DNS 批量并行排查清点已进度达到 $([math]::Min($i + $chunkSize, $tempOptimized.Count)) 项 ..."
    }
}

$eliminatedDeadCount = ($tempOptimized.Count - $optimizedRules.Count)
Write-Log "========================================"
Write-Log "DNS清理任务完成。排爆无效的失连/失效规则广告域名拦截：淘汰释放清理多达 $eliminatedDeadCount 个废弃链接占用!"

# 对最终活口成功上墙过滤网兜的剩余存量域名对拍生成标准 YAML 文件块的 Clash语法数组格式
$formattedRules = $optimizedRules | Sort-Object | ForEach-Object { "- '+.$_'" }

$ruleCount = $optimizedRules.Count
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 创建 YAML 内容
$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime (UTC+8)
# DNS Validation Completed. Automatically cleared dead or inaccessible subdomains out: $eliminatedDeadCount.
# Generated valid live AdBlock domains total entries rules: $ruleCount

payload:
$($formattedRules -join "`n")
"@

# 定义输出文件路径并写入
$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$textContent | Out-File -FilePath $outputPath -Encoding utf8

Write-Log "转换完成打包部署生效就位！验证剩余高质量可用阻拦生成总计个数是 : $ruleCount"
Write-Log "规则已完整封印持久输出写存保存落锁完毕至 : $outputPath"
