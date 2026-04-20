#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Title: AdBlock_Rule_For_Clash 极速优化与人类易读版
# Description: Clash 广告拦截规则生成脚本 (多线程超快提速版 + 清晰日志版)

import os
import re
import urllib.request
import datetime
import sys
import concurrent.futures

# 修复在某些系统终端下的中文打印乱码问题
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# === 自定义全局白名单 ===
# 如果你有绝对不能被拦截的域名，直接写在这里
custom_excluded_domains = [
    # "example.com",
    # "taobao.com"
]

# === 按规则质量分级的订阅源 ===
allow_urls = [
  # "https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/white.txt"
]

tier1_urls = [
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt"
]

tier2_urls = [
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylist.txt"
]

tier3_urls = [
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt"
]

# 自动获取当前脚本所在的目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "adblock_log.txt")

# 如果之前存在日志文件，先把它删掉，从头写起
if os.path.exists(LOG_FILE_PATH):
    try:
        os.remove(LOG_FILE_PATH)
    except OSError:
        pass

def write_log(message):
    """写日志小工具：在屏幕打印的同时，保存到文本里，方便以后查看。"""
    print(message)
    time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
        f.write(f"{time_str} - {message}\n")

# 定义一个检查域名的正规格式表达式，不符合正常拼写标准的都会被拒收
domain_regex = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')

# 🚀 极其好用的核心解析规则大全，能够一秒自动读懂别人写的各大类型的拦截名单，准确抠出主域名
pattern_extractor = re.compile(
    r"^(?:"
    r"\|\|([a-zA-Z0-9.-]+)(?:\^.*)?$|"                           # 抓取第一类：带 ||xxx.com^ 后缀结尾的情况
    r"(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+).*|"    # 抓取第二类：用类似 0.0.0.0 的旧方法强制屏蔽指向的情况 
    r"(?:address|server)=/([a-zA-Z0-9.-]+)/.*|"                  # 抓取第三类：部分以 Dnsmasq 服务直接指认的形式
    r"DOMAIN(?:-SUFFIX)?,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}).*|"   # 抓取第四类：大家熟知的常规 Clash / Surge 后缀标准模式！
    r"([a-zA-Z0-9.-]+)$"                                         # 抓取第五类：光溜溜的一个裸拼写法域名 (没别的干扰)
    r")"
)

def fetch_and_parse(url):
    """自动找对应网络链接里的东西并把它归置出来"""
    logs = [f"准备从链接下载并拆解分析名单: {url}"]
    ad_domains, white_domains = set(), set()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"}
    
    req = urllib.request.Request(url, headers=headers)
    try:
        # 只给15秒，网络不通我们立马断，以免这死链接拖后腿让运行死住不动
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        logs.append(f"❌ 这个网址现在抽风了连不上，自动跳过它不管 - {url} : {e}")
        return url, ad_domains, white_domains, logs

    for line in content.splitlines():
        line = line.strip()
        # 处理空行及乱入带!带#的解释说明批注行
        if not line or line[0] in "![#": 
            continue

        is_whitelist = line.startswith("@@")
        if is_whitelist:
            line = line[2:]

        m = pattern_extractor.match(line)
        if m:
            # 找到对应的主词儿之后把它统归纳入囊
            domain = m.group(m.lastindex)
            if domain_regex.match(domain):
                # 以防大家瞎用大小写造误，我帮大家全切回常见小写形态
                domain = domain.lower()
                if is_whitelist:
                    white_domains.add(domain)
                else:
                    ad_domains.add(domain)
    
    logs.append(f"✔️ 下载并抓取整理完成了！- {url} \n    (本次提取发现 🚫拦截网址: {len(ad_domains)} 条, 🛡️放行网址: {len(white_domains)} 条)")
    return url, ad_domains, white_domains, logs

def process_url_group(urls, pool):
    """管辖上面的工人一块下载的大统管中心。汇总多线发上来的结果。"""
    all_ad, all_wh = set(), set()
    if not urls: 
        return all_ad, all_wh
        
    results = pool.map(fetch_and_parse, urls)
    for url, ads, whs, logs in results:
        # 发给小日志器保存报告屏幕进程情况
        for log in logs: 
            write_log(log)
        all_ad.update(ads)
        all_wh.update(whs)
    return all_ad, all_wh

def get_ancestors(domain):
    """自动分解出一个网站可能的大分类父网站: 假如说是 m.ad.taobao.com 则拆出来就是 ad.taobao.com 然后再 taobao.com """
    idx = domain.find('.')
    while idx >= 0 and idx < len(domain) - 1:
        yield domain[idx + 1:]
        idx = domain.find('.', idx + 1)

def main():
    write_log("\n==== 开始跑脚本了: 第一件事优先看你有啥要免受杀误截的重要本子设定。 ====")

    # 初始化收集袋 (采用Python内置极其优秀的极速 Set 高速集合操作模式提振效率)
    white_set = set(d.lower() for d in custom_excluded_domains)
    core_set_raw, tier3_set_raw = set(), set()
    top_whitelist = set()

    # 首先去家里面（当前路径）看看有没有顶头绝对安全放宽处理不可拦截主文档白皮书
    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        with open(top_whitelist_file, "r", encoding="utf-8") as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith("#"):
                    d_lower = domain.lower()
                    top_whitelist.add(d_lower)
                    white_set.add(d_lower)
                    
        success_msg = f"本地有 [高权重白皮保护伞: top_whitelist.txt]，一共纳入受保护网址主单名数了: [{len(top_whitelist)}] 记录条！它们后续哪怕怎么判黑也能活下来受权畅用!"
        print(f"\033[36m{success_msg}\033[0m") 
        write_log(success_msg)

    # ========================== 抓紧开启高网速抓拉并行 =========================== 
    # 计算全部网页一共用总的并发行数目开线程大锅齐齐出马避免死挨卡：
    all_req_cnt = len(allow_urls) + len(tier1_urls) + len(tier2_urls) + len(tier3_urls) + 1
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, all_req_cnt)) as executor:
        
        write_log("\n【步骤 1】：处理全局统筹防过白特控来源名单池获取...")
        ad_ext, wh_ext = process_url_group(allow_urls, executor)
        core_set_raw.update(ad_ext); white_set.update(wh_ext)

        write_log("\n【步骤 2】：处理绝对靠前防备级核心列表项群池取货提取任务：包含高强度核发层来源表...")
        all_core_urls = tier1_urls + tier2_urls
        ad_ext, wh_ext = process_url_group(all_core_urls, executor)
        core_set_raw.update(ad_ext); white_set.update(wh_ext)

        write_log("\n【步骤 3】：拓展源项补入提收库发抓行动开启: 主针对其他三配表级扩展级查堵拦截源收缴并集构建..")
        ad_ext, wh_ext = process_url_group(tier3_urls, executor)
        tier3_set_raw.update(ad_ext); white_set.update(wh_ext)
    # =======================================================================


    # ======= 后台洗地机制（过滤重名+提去死扣错误逻辑部分清理段项）=========
    write_log("\n>> 马上来清空并简化上面三步拉取海量网址时那些冲突了跟互相叠架冗余的信息结构 ...")
    
    # 策略 1: 把要封的和不打算封的安全对象错落避开；如果在它祖宗上有安全证明在手的就免它入围了防无心击错宽泛受罪牵连；
    valid_core_domains = {
        d for d in core_set_raw 
        if d not in white_set and not any(anc in white_set for anc in get_ancestors(d))
    }
    
    # 如果抓进来了一大票类似 ad.qq.com, qq.com... 如果存在更明确的屏蔽细节，宁舍最总的以免直接让人家没法正常打开访问宽全平台：去除了把范围说大扯远的节点，仅留短截切要害处保留明查。
    core_sub_detect_cache = {
        anc for d in valid_core_domains for anc in get_ancestors(d)
    }

    optimized_core_set = {
        d for d in valid_core_domains if d not in core_sub_detect_cache
    }

    # ======== 构建防御盾（白名单与核单结合伞向）：===================== 
    write_log(">> 系统正在撑开保护伞屏防体系建立保护库网络免它下限牵联，为扩展级剔源做保靠防波做指路伞列网护.......")
    protected_ancestors = set()
    for subset in (white_set, optimized_core_set):
        for item in subset:
            protected_ancestors.add(item)
            protected_ancestors.update(get_ancestors(item))


    # ======= 在此基础之上验证处理不听话或者过度阻宽面截源扩扩展补配向清理 ======
    write_log(">> 现在在理干净处理三阶段新加的一批辅助杂规则（避免由于扩库配单过狠而无视错位大名单放生区直接给全端弄不亮的问题！）......")
    
    temp_tier3_valid_domains = {
        d for d in tier3_set_raw 
        if d not in protected_ancestors and not any(anc in white_set for anc in get_ancestors(d))
    }
    
    tier3_sub_detect_cache = {
        anc for d in temp_tier3_valid_domains for anc in get_ancestors(d)
    }

    optimized_tier3_set = {
        d for d in temp_tier3_valid_domains if d not in tier3_sub_detect_cache
    }
    

    # ==== 最后合成输出收紧口关闸了排期并处理 ====
    write_log(">> 到此所有网络清洗结束收编合一总出并出结验成收拢表集大关检核开始........")
    
    pre_combined = set(optimized_core_set)
    pre_combined.update(optimized_tier3_set)

    global_subs_detector = {
        anc for d in pre_combined for anc in get_ancestors(d)
    }

    # 合排在一起进行字母规归纳好看清排清整排序展示（顺畅发单落成格式）。
    final_combined_rules = sorted([
        d for d in pre_combined if d not in global_subs_detector
    ])

    formatted_rules = [f"- '+.{domain}'" for domain in final_combined_rules]
    rule_count = len(formatted_rules)

    write_log("\n-----------------------[ 🎉最后出果汇报！总结大黑榜账期结册生成账面] --------------------------")
    write_log(f"📋[总出基本拦截数目]: 最强安全池级防打底源清理打整后的基数包含 -> [{len(optimized_core_set)}] 条数据源。")
    write_log(f"📋[第三阶段收来副包外接单源拓展]：剔除非要死磕被我们拒下的，包含着入档数为   -> [{len(optimized_tier3_set)}] 条辅源辅助拦截包点单记录！。")
    write_log(f"💎[双向会师去去繁化后收汇总记]: 当前一共提取去配清出明确可执行有效拦截的精准防源是 -> {rule_count} 条可安全被使用记录集出。完美成套截果出。！")

    utc_time = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    generation_time = utc_time.strftime("%Y-%m-%d %H:%M:%S")

    # Yaml 文件构建声明主体 兼容各种 Clash 系列终端不崩溃版本结构落配置信息标体记号配源向：
    text_content = f"""# Title: AdBlock_Rule_For_Clash 极优护防强清核净本版机制
# Description: 专门服务各类客户端版本 Clash 体系去脏流安全源排过滤净集域名截停库
# Homepage: https://github.com/Filterrr/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/Filterrr/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# Generated on: {generation_time} (当前使用换算后的 UTC+8 标报记录节点出点日产间期发成排统管结项管理列落归报志表志标布结出)
# 已在防保护拦截防杀受重点免设拦截列保名名单总控权数为: {len(top_whitelist)} 项域名。
# 今日所总下设归库可成册截打杀目标域配管条结源数为共有：{rule_count} 条排排条点记账查统列！

payload:
""" + "\n".join(formatted_rules) + "\n"

    # 把弄出来的文本落袋发生成出你身边本地所在文件：adblock_reject.yaml   
    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text_content)

    write_log(f"\n✅ 终于完美收尾全活收场收工拉了老板！！最终生成的文件格式完全规整好已经放在了电脑硬盘的这一级位置: ->  [ {output_path} ] \n感谢支持选用运行使用，用最简洁方式带回最优过滤防护成果~！")


if __name__ == "__main__":
    main()
