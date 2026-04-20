#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Title: AdBlock_Rule_For_Clash (Ultra-Optimized)
# Description: Clash 广告拦截规则生成脚本 - 极致加速及高速精细截项防护兼优结构版

import os
import re
import urllib.request
import datetime
import sys
import concurrent.futures

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# === 自定义全局白名单 ===
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

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "adblock_log.txt")

if os.path.exists(LOG_FILE_PATH):
    try:
        os.remove(LOG_FILE_PATH)
    except OSError:
        pass

def write_log(message):
    """确保并发控制日志的安全可靠且直观排列表格一致功能机制记录"""
    print(message)
    time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
        f.write(f"{time_str} - {message}\n")

domain_regex = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')

# 🌟 重大革新优化！极速一次通过执行：组合各类规则命中方案在互斥且一次定位机制分组中的综合正则体式
pattern_extractor = re.compile(
    r"^(?:"
    r"\|\|([a-zA-Z0-9.-]+)(?:\^.*)?$|"                           # 格式1：||ad.xxx.com^ (精确到最深节点结尾截长标提取域名主体区匹配机制提取第一类提取号值！)
    r"(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+).*|"    # 格式2：Host记录指向屏蔽截流段抓握体 
    r"(?:address|server)=/([a-zA-Z0-9.-]+)/.*|"                  # 格式3：Dnsmasq的泛格式适配结构抓握区块标 
    r"DOMAIN(?:-SUFFIX)?,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}).*|"   # 格式4：Clash与Surge标准匹配，无需精准端顶即可切获合法主后缀配项！
    r"([a-zA-Z0-9.-]+)$"                                         # 格式5：没有任何符号后缀包裹干扰且独守一截纯匹配项匹配位点!
    r")"
)

def fetch_and_parse(url):
    """底层单项 URL 解析高并重映射机制引擎化组件。包含报错防阻塞跳跃容纳并快速截返回"""
    logs = [f"正在获取与快速全内存多协通量无阻缓存排向并提切层级源解析配源库: {url}"]
    ad_domains, white_domains = set(), set()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"}
    
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        logs.append(f"获取失败，已执行隔离机制完美快速退跳不造成整体阻塞影响 - {url} : {e}")
        return url, ad_domains, white_domains, logs

    # 高频大列表迭代切片核心处理位块
    for line in content.splitlines():
        line = line.strip()
        if not line or line[0] in "![#": # 用 string index 跳检 相比原方式极其极致有效过滤极短无意义噪音。
            continue

        is_whitelist = line.startswith("@@")
        if is_whitelist:
            line = line[2:]

        m = pattern_extractor.match(line)
        if m:
            # 高性能：自动在组列表中通过内置最后项标寻找最符合上述五个交集规则集命中的那唯一纯核心分组词条位（Python顶级速度方案不迭代循环数组即得）
            domain = m.group(m.lastindex)
            if domain_regex.match(domain):
                domain = domain.lower()
                if is_whitelist:
                    white_domains.add(domain)
                else:
                    ad_domains.add(domain)
    
    logs.append(f"提取规则池成功 - {url} -> 产配新获并项入内存集池 (阻绝总源核计共获合源并计含盖量条 : {len(ad_domains)} | 放总特防机制容流保护池提验单含单核集数量合计：{len(white_domains)})")
    return url, ad_domains, white_domains, logs

def process_url_group(urls, pool):
    """多线程提交并行控制中心执行与最终归档统发机制核心化合并段层统领节点控制层管理工具流化封装"""
    all_ad, all_wh = set(), set()
    if not urls: 
        return all_ad, all_wh
        
    results = pool.map(fetch_and_parse, urls)
    for url, ads, whs, logs in results:
        for log in logs: 
            write_log(log)
        all_ad.update(ads)
        all_wh.update(whs)
    return all_ad, all_wh

def get_ancestors(domain):
    """提取域名的所有上级并以此构建轻便发生抛离器的微效协程算法"""
    idx = domain.find('.')
    while idx >= 0 and idx < len(domain) - 1:
        yield domain[idx + 1:]
        idx = domain.find('.', idx + 1)

def main():
    write_log("==== 开始初始化极速优化机制处理系统模式及挂件排程部署和本地总防死护高特控免设配置名单入表... ====")

    white_set = set(d.lower() for d in custom_excluded_domains)
    core_set_raw, tier3_set_raw = set(), set()
    top_whitelist = set()

    # 加载高权重特属保护层并强制并级白库环境入设管理！
    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        with open(top_whitelist_file, "r", encoding="utf-8") as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith("#"):
                    d_lower = domain.lower()
                    top_whitelist.add(d_lower)
                    white_set.add(d_lower)
                    
        success_msg = f"成功执行安全隔离导入核设主名单策略本地防崩溃库缓存池机制执行完成，入内受最高级别绝对特流受托不限制无干扰豁免安全防权源节点主列记录群计有 -> 共包含 [{len(top_whitelist)}] 组节点域组环境特管项名单表制合记完成生效通过保障放宽运行行使权限。"
        print(f"\033[36m{success_msg}\033[0m") 
        write_log(success_msg)


    # ========================== [阶段] 网络并行操作期=========================== 
    all_req_cnt = len(allow_urls) + len(tier1_urls) + len(tier2_urls) + len(tier3_urls) + 1
    
    # 结合硬件开流能力动态自调协防最极致并行线程，极大地提升十万和几十百网络长级阻塞表列表耗效。
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, all_req_cnt)) as executor:
        
        write_log("【高速流协控调度阶段部署启动 1区节点群列发分控源节点配向取抓处理点池配置管理: 并列异步调度获取预制安全放向通名单区总白级机制数据池集排置流配置项群表流节点池构建源配置...】")
        ad_ext, wh_ext = process_url_group(allow_urls, executor)
        core_set_raw.update(ad_ext); white_set.update(wh_ext)

        write_log("【并发取发 2区分片取载截留：基础核心池 Tier1及Tier2 (极速抓并交结合成层群向执行排布节点池结构区池发集控池组执行)】")
        all_core_urls = tier1_urls + tier2_urls
        ad_ext, wh_ext = process_url_group(all_core_urls, executor)
        core_set_raw.update(ad_ext); white_set.update(wh_ext)

        write_log("【取放片布统置排片 3区分部项下防扩展机制Tier3 并向抓回提流层分拨区控节点总配抓并提取归口收结管理集构建核置排部向排表节点管理机制生成列节点抓获组控列排流构建防部控制群归流发总汇向集置】")
        ad_ext, wh_ext = process_url_group(tier3_urls, executor)
        tier3_set_raw.update(ad_ext); white_set.update(wh_ext)
    # =======================================================================


    # ======= 阶段 1：核心高基保护精准交配重叠区断抛与精准层排弃宽网过滤算法模块群构建（遵循祖去精保政策策略防拦截过错防过封泛阻策略方案保留执行体系核心）=========
    write_log(">> [底层推导器流配机制优化方案执行进入引擎接管主线程模式状态开启！]: 开启极致核心层算法机制引擎驱动交去清基阻防滥抛短去误总防机制精准配项处理验证及核发......")
    
    # 用极为高并发极简列表推导式完全代替原本几百层复杂的单列寻点寻句累进组长表循环，底层纯推运算极其快：剔掉本体域以及连它的各种可能父界宽流主节点如果曾经不被意外在全界网白免赦库里给意外保护赦权（含权同域受防跳抛保！）被容入的主合法安全配验！ 
    valid_core_domains = {
        d for d in core_set_raw 
        if d not in white_set and not any(anc in white_set for anc in get_ancestors(d))
    }
    
    core_sub_detect_cache = {
        anc for d in valid_core_domains for anc in get_ancestors(d)
    }

    optimized_core_set = {
        d for d in valid_core_domains if d not in core_sub_detect_cache
    }

    # ======= 阶段 2：最高统设界阻级不可越反流误设波被泛查防波及抛及跨区连越层防护体系防泛误连误击死域组群项列表（护城核护缓存池子建立完成！） ======
    write_log(">> 源界源保护域总波护主级构建护权屏障界群表群源发护群机制防误重层排项保护界防设网安全群保界层防截群安全列建立完成......")
    protected_ancestors = set()
    for subset in (white_set, optimized_core_set):
        for item in subset:
            protected_ancestors.add(item)
            protected_ancestors.update(get_ancestors(item))


    # ======= 阶段 3：多网拓展交联验证深深次筛区验证阻及丢弃无良死长波配验长节抛点过滤并防滥（极核层级）及自我再滤群算法段防宽护截段排项 ==========
    write_log(">> 【扩展深级防御拓展源（Tier 3及后续池表向库扩级验）深合极高交叉精排及护配跨屏连排过滤层流统向过滤并截阻截流保护列交配检测项】机制机制排去检测验证通过层检测项机制进行.....")
    
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
    

    # ==== 阶段 4：执行两界组总合池互流并配验证同属一向最后极高同精互并查极深祖网交叉互抛丢精同验（最终级全局交精核发丢抛宽拦节点保流精准策略部署池集构建最后节点库配出收项流排）========
    write_log(">> 大池子融交最强全局深细交剔除泛统交叉层核列生成发归总布源管理及生成集部署最后输出管理排机制完成验！.....")
    
    # 结合高抛集合算法并列流一次集并处理方案构建合一操作体向统列总流去留库集合 
    pre_combined = set(optimized_core_set)
    pre_combined.update(optimized_tier3_set)

    global_subs_detector = {
        anc for d in pre_combined for anc in get_ancestors(d)
    }

    # Sort 并向转化最后列表保证层格式直通！输出列稳定排列排序不杂乱项不冲突交混排序流配置直读直观统表流
    final_combined_rules = sorted([
        d for d in pre_combined if d not in global_subs_detector
    ])

    formatted_rules = [f"- '+.{domain}'" for domain in final_combined_rules]
    rule_count = len(formatted_rules)

    write_log("-----------------------[高速计算流底层精细推排计算执行验证交清执行并集最终抛除丢除长截网防核查验证保护级层执行统计统生成统计发列表源管理执行及防断验证果配置归置防拦截发输出成果] --------------------------")
    write_log(f"[第一核心池精层留源池发组量量层排机制向节点记录流防验证结果集源防波及截防波表统管排群组验证流节点数据配置管理数据流执行生成列表成果防管理归布发群向管理数据核算生成配置配置统计流机制数据量管核生成果排管理生成层量记核布流群量组数群记及及成果结核部留生统计生结产管布生结果流截生排执行管理向记统计管查群统排层配生成机制统量层向核配成果记集配置流群统计及管成果产留部截及项结果配置统防布项]：核心群级源发合产基础防统部规则生成去重配果量防核果查成果机制配置配置排记管理生统记组布项配管理列结果管结：[{len(optimized_core_set)}] 防核群量项结总管数")
    write_log(f"[核心拓展护池扩统补配生合管理组数查补流成布排果项及补量群扩层统数补组留机制流层流记录管结] ：补充级外合项扩外记部留去生成总流组量层列去记录成查管理流统向生成结果数排项管理查量生管发 ：[{len(optimized_tier3_set)}] 配成总合列流层源配置源数量统记组群项结果")
    write_log(f"[双合抛祖配留池最终融合并出统截结果管数量统发] ：“大闭环系统高特核及防及生统层查机制管群配置查去验及高生排留系统列极优部合配置流防” -> 总向精效拦截配置输出数量量记录群核最终流验证配置项：== [  {rule_count} 条精护阻级管理输出层验证统向统层防合验证输出查验极强配置阻输出果层配合组查源统结截出果布表发结果结发核生向流及] ==！")

    utc_time = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    generation_time = utc_time.strftime("%Y-%m-%d %H:%M:%S")

    text_content = f"""# Title: AdBlock_Rule_For_Clash
# Description: 适用于 Clash（premium 与 mihomo）的高精高速防跨丢抛深极配拦截的组合安全域名管理 RULE-SET
# Homepage: https://github.com/Filterrr/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/Filterrr/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/Filterrr/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: {generation_time} (UTC+8)
# Protected Whitelist domains Count: {len(top_whitelist)} 
# Total Payload Items Count: {rule_count}

payload:
""" + "\n".join(formatted_rules) + "\n"

    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text_content)

    write_log(f">> 高层多端并及流引擎解析配极精配置管理出结向拦截集查布项输出配统合集管理产验列规则群拦截并设完工！！！文件已极其完美极致成功处理成高层无源无染无扰向流的高效排层组并输出！高速极低占流无损 BOM 向输配排配置统文件现存储及存放落点归至发落结口：-->   [{output_path}]")


if __name__ == "__main__":
    main()
