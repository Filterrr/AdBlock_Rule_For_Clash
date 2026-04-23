#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Title: AdBlock_Rule_For_Clash
# Description: Clash 广告拦截规则生成脚本
# 功能：自动屏蔽广告，保障网络稳定畅通。

import os
import re
import urllib.request
import datetime
import sys

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# === 自定义全局白名单 ===
custom_excluded_domains = [
    # "example.com",
    # "taobao.com"
]

# === 按规则质量分级的订阅源 ===
allow_urls = [
 #   "https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/white.txt"
]

tier1_urls = [
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt"
]

tier2_urls = [
  #  "https://easylist-downloads.adblockplus.org/easylistchina.txt",
  #  "https://easylist-downloads.adblockplus.org/easylist.txt"
]

tier3_urls = [
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt"
]

# 获取当前运行目录的绝对路径
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "adblock_log.txt")

# 初始化 / 清理之前的日志文件
if os.path.exists(LOG_FILE_PATH):
    try:
        os.remove(LOG_FILE_PATH)
    except OSError:
        pass

def write_log(message):
    """日志控制台流双通打印写入函数"""
    print(message)
    time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
        f.write(f"{time_str} - {message}\n")

# 定义和预编译处理格式数据和正则引擎，提高效率
domain_regex = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')

regex1 = re.compile(r'^\|\|([a-zA-Z0-9.-]+)(?:\^.*)?$')
regex2 = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+)')
regex3 = re.compile(r'^(?:address|server)=/([a-zA-Z0-9.-]+)/')
regex4 = re.compile(r'^(?:DOMAIN|HOST)(?:-SUFFIX)?\s*,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:\s*,.*)?$', re.IGNORECASE)
regex5 = re.compile(r'^([a-zA-Z0-9.-]+)$')

def extract_rules(urls, rules_set, global_whitelist):
    """提取 URL 文件信息内有效域名至目标集合内的模块工具（支持内置拦截模式去重并提取规则）"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    }
    
    for url in urls:
        write_log(f"正在获取: {url}")
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                content = response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            write_log(f"获取失败，已跳过 - {url} : {e}")
            continue

        for line in content.splitlines():
            line = line.strip()
            # 跳过空行及各种类型的特殊头部行及纯注释符
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                continue

            # 处理白名单判断标识：是否具有双@符
            is_whitelist = line.startswith("@@")
            if is_whitelist:
                line = line[2:]

            domain = None
            
            # 使用 Switch 功能模拟执行各类情况（按照严格先后优先级的依次匹配机制）：
            if m := regex1.match(line): domain = m.group(1)
            elif m := regex2.match(line): domain = m.group(1)
            elif m := regex3.match(line): domain = m.group(1)
            elif m := regex4.match(line): domain = m.group(1)
            elif m := regex5.match(line): domain = m.group(1)

            if domain and domain_regex.match(domain):
                # 以规避大小写带来混用风险将其统一强制小写转化插入
                domain = domain.lower()
                # @@ 的判定如果成功放入指定总白名单集合：否则投入普通解析缓存区集。
                if is_whitelist:
                    global_whitelist.add(domain)
                else:
                    rules_set.add(domain)

def main():
    write_log("==== 开始初始化设置和本地白名单 ====")

    # 使用 set 可以拥有跟原生 .Net HashSet（基于哈希）对等快速检索处理的相同时间优势！
    white_set = set(d.lower() for d in custom_excluded_domains)
    core_set_raw = set()
    tier3_set_raw = set()

    # ====== 加载外部核心白名单 ======
    # 功能：加载高权重域名白名单（top_whitelist.txt），防止被规则误杀
    top_whitelist = set()
    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        with open(top_whitelist_file, "r", encoding="utf-8") as f:
            for line in f:
                domain = line.strip()
                # 过滤空行和带有 # 的注释内容
                if domain and not domain.startswith("#"):
                    domain_lower = domain.lower()
                    top_whitelist.add(domain_lower)
                    
                    # 将这些域名加入全局白名单，防止被拦截
                    white_set.add(domain_lower)
        success_msg = f"成功加载本地高权重白名单文件，共包含 [{len(top_whitelist)}] 个域名！"
        print(f"\033[36m{success_msg}\033[0m") # 输出终端天蓝色作为特定提示点（若受系统终端兼容限制无影响仅作显示使用）。
        write_log(success_msg)
    # ====== 核心白名单加载完成 ======

    write_log("【步骤 1: 获取预设及在线全局白名单】")
    extract_rules(allow_urls, core_set_raw, white_set)

    write_log("【步骤 2: 获取基础保护规则 (Tier 1 / Tier 2)】")
    all_core_urls = tier1_urls + tier2_urls
    extract_rules(all_core_urls, core_set_raw, white_set)

    write_log("【步骤 3: 获取扩展补充规则 (Tier 3)】")
    extract_rules(tier3_urls, tier3_set_raw, white_set)

    # ======= 阶段 1：处理基础规则 (清理去重) =========
    write_log(">> 正在清理基础规则中的冲突和冗余内容...")
    
    # [逻辑重构] 白名单核准检测 - 对源数组去伪预排获取基础有效条目
    valid_core_domains = set()
    for domain in core_set_raw:
        if domain in white_set:
            continue
        is_whitelisted = False
        dot_index = domain.find('.')
        while dot_index >= 0 and dot_index < len(domain) - 1:
            if domain[dot_index + 1:] in white_set:
                is_whitelisted = True
                break
            dot_index = domain.find('.', dot_index + 1)
        if not is_whitelisted:
            valid_core_domains.add(domain)

    # [规则修改核心] 遍历统计并缓存“处于别人主域名段（充当基础父级环境）的主域名节点记录防一拍切所有防过错！”。如果发下存在自己也同拥包含具体细节域名则舍自己短项取最准度深子规则防阻塞所有
    core_sub_detect_cache = set()
    for domain in valid_core_domains:
        dot_index = domain.find('.')
        while dot_index >= 0 and dot_index < len(domain) - 1:
            core_sub_detect_cache.add(domain[dot_index + 1:])
            dot_index = domain.find('.', dot_index + 1)

    optimized_core_set = set()
    for domain in valid_core_domains:
        # 当检查自己具备且映射进被附属的主域包含池子缓存内（此长节点已被登记为属于某种长级项前项或祖籍根环境） -> 表示其内拥有属于自己具体且指定的衍生级深段。依照精确保配取舍制即时防混舍去避免过线泛滥断点遮流直接不采用该顶！(保留较精更明确节点)。
        if domain in core_sub_detect_cache:
            continue
        optimized_core_set.add(domain)

    # ======= 阶段 2：构建防误杀保护机制 =========
    write_log(">> 正在生成重点防护名单，防止重要域名被意外拦截...")
    protected_ancestors = set()
    # 提取出白名单与核心规则的所有父级域名缓存组册群保证：如果这中间具备某一层不能越界（封锁所有）的界线。他们都不会由于第三序列牵挂封阻关联群！
    for subset in (white_set, optimized_core_set):
        for item in subset:
            c_dom = item
            protected_ancestors.add(c_dom)
            while True:
                idx = c_dom.find('.')
                if idx < 0 or idx >= len(c_dom) - 1:
                    break
                c_dom = c_dom[idx + 1:]
                protected_ancestors.add(c_dom)

    # ======= 阶段 3：过滤并合并扩展规则 (Tier 3) =========
    write_log(">> 正在检测扩展规则，排除与保护名单冲突的内容...")
    
    temp_tier3_valid_domains = set()
    for domain in tier3_set_raw:
        # 检测是否跟已经设定为免越界死角的根父拦截防护区一致
        if domain in protected_ancestors:
            continue

        should_discard = False
        dot_index = domain.find('.')
        while dot_index >= 0 and dot_index < len(domain) - 1:
            parent = domain[dot_index + 1:]
            # 放行包含跨界子结构拦截匹配请求：这里原逻辑跟 Core 级别判错直接拦截不同！要遵循有详细优先策略。
            # 这里只需且完全保证不受主界全环境下的 白名单 安全覆盖即可安全流入子级别。如果被下辖保护死顶也应当排除出避免防同影响防漏遮截。
            if parent in white_set:
                should_discard = True
                break
            dot_index = domain.find('.', dot_index + 1)

        if not should_discard:
            temp_tier3_valid_domains.add(domain)

    # 在内部对第三层扩展的规则域做子附同前部防查归根精化取去丢横粗段等项：
    tier3_sub_detect_cache = set()
    for domain in temp_tier3_valid_domains:
        dot_index = domain.find('.')
        while dot_index >= 0 and dot_index < len(domain) - 1:
            tier3_sub_detect_cache.add(domain[dot_index + 1:])
            dot_index = domain.find('.', dot_index + 1)
            
    optimized_tier3_set = []
    for domain in temp_tier3_valid_domains:
        if domain in tier3_sub_detect_cache:
            continue
        optimized_tier3_set.append(domain)

    # ==== 阶段 4：执行两库模块联全合及统一跨维级最后抛粗子留主存检测去配整合项 ====
    write_log(">> 执行两极互配互防验证抛丢拦截合并操作组并列整合完成库级数据...")
    pre_combined = list(set(list(optimized_core_set) + optimized_tier3_set))
    
    # 彻底执行“具有任何存在具体防下端指则去大级抛祖级别节点”，若两极组合存在此段干连情况也完美触发此抛切机制确保纯级具体留定策略。
    global_subs_detector = set()
    for domain in pre_combined:
        dot_index = domain.find('.')
        while dot_index >= 0 and dot_index < len(domain) - 1:
            global_subs_detector.add(domain[dot_index + 1:])
            dot_index = domain.find('.', dot_index + 1)
            
    final_combined_rules = [domain for domain in pre_combined if domain not in global_subs_detector]
    final_combined_rules.sort()
    
    # 拼接并重叠YAML对应要求格式的预处理机制化载体表（即 "- '+.$_'" 在 Python 的逻辑表态处理项组）
    formatted_rules = [f"- '+.{domain}'" for domain in final_combined_rules]
    rule_count = len(formatted_rules)

    write_log("-----------------------[最终统计结果] --------------------------")
    write_log(f"[基础规则] : 初步去重后的基础拦截规则   -> 共计 : {len(optimized_core_set)} 条")
    write_log("[保护机制] : 本地白名单防误杀保护       -> 已成功生效")
    write_log(f"[扩展规则] : 初步去重后的补充扩展规则   -> 共计 : {len(optimized_tier3_set)} 条")
    write_log(f"[最终统计] : 全局防泛滥精切机制优先验并 -> 总计生成 : {rule_count} 条精准拦截源配规则段！")

    # 对等换算为 (UTC+8) 的执行操作当地日期时间戳构建标签声明区文本标。
    utc_time = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    generation_time = utc_time.strftime("%Y-%m-%d %H:%M:%S")

    # Yaml 文件构建声明主体。保持了完全一致的无BOM生成协议以实现完美的 clash 加载防崩溃验证方案格式内容支持
    text_content = f"""# Title: AdBlock_Rule_For_Clash
# Description: 适用于 Clash（premium 与 mihomo）的广告域名拦截 RULE-SET 规则集，每天更新一次
# Homepage: https://github.com/Filterrr/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/Filterrr/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/Filterrr/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: {generation_time} (UTC+8)
# Protected Whitelist domains Count: {len(top_whitelist)} 
# Total Payload Items Count: {rule_count}

payload:
""" + "\n".join(formatted_rules)

    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    
    # 存出写操作 (Python 在 utf-8 参数标准写入时默认本身为无 Bom 生成器, 此设计无需引用外界封装流配置, 简洁有效 )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text_content)

    write_log(f">> 广告拦截规则处理完成！已导出为无 BOM 格式，文件保存在: {output_path}")


if __name__ == "__main__":
    main()
