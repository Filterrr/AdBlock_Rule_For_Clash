#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Title: AdBlock_Rule_For_Clash
# Description: Clash 广告拦截规则生成脚本
# 功能：自动屏蔽广告及 DNS 垃圾/遥测规则，保障网络稳定畅通。

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

# === [新增] DNS 过滤垃圾/遥测/跟踪规则源 ===
# 选用了业界公认低误杀的 Hagezi 和 Steven Black 列表
junk_urls = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt", # Hagezi Light: 极低误杀，拦截广告与追踪
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",               # 经典 Hosts 拦截集 (含广告/恶意软件)
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

# 定义和预编译处理格式数据和正则引擎
domain_regex = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')
regex1 = re.compile(r'^\|\|((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?:\^.*)?$')
regex2 = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+)')
regex3 = re.compile(r'^(?:address|server)=/([a-zA-Z0-9.-]+)/')
regex4 = re.compile(r'^(?:DOMAIN|HOST)(?:-SUFFIX)?\s*,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:\s*,.*)?$', re.IGNORECASE)
regex5 = re.compile(r'^([a-zA-Z0-9.-]+)$')

def extract_rules(urls, rules_set, global_whitelist):
    """提取 URL 文件信息内有效域名至目标集合"""
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
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                continue

            is_whitelist = line.startswith("@@")
            if is_whitelist:
                line = line[2:]

            domain = None
            if m := regex1.match(line): domain = m.group(1)
            elif m := regex2.match(line): domain = m.group(1)
            elif m := regex3.match(line): domain = m.group(1)
            elif m := regex4.match(line): domain = m.group(1)
            elif m := regex5.match(line): domain = m.group(1)

            if domain and domain_regex.match(domain):
                domain = domain.lower()
                if is_whitelist:
                    global_whitelist.add(domain)
                else:
                    rules_set.add(domain)

def main():
    write_log("==== 开始初始化设置和本地白名单 ====")

    white_set = set(d.lower() for d in custom_excluded_domains)
    core_set_raw = set()
    tier3_set_raw = set()

    top_whitelist = set()
    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        with open(top_whitelist_file, "r", encoding="utf-8") as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith("#"):
                    domain_lower = domain.lower()
                    top_whitelist.add(domain_lower)
                    white_set.add(domain_lower)
        success_msg = f"成功加载本地高权重白名单文件，共包含 [{len(top_whitelist)}] 个域名！"
        print(f"\033[36m{success_msg}\033[0m")
        write_log(success_msg)

    write_log("【步骤 1: 获取预设及在线全局白名单】")
    extract_rules(allow_urls, core_set_raw, white_set)

    write_log("【步骤 2: 获取基础保护规则 (Tier 1 / Tier 2)】")
    all_core_urls = tier1_urls + tier2_urls
    extract_rules(all_core_urls, core_set_raw, white_set)

    write_log("【步骤 3: 获取扩展补充规则 (Tier 3)】")
    extract_rules(tier3_urls, tier3_set_raw, white_set)

    # === [新增步骤 4] 获取 DNS 垃圾/遥测规则 ===
    write_log("【步骤 4: 获取 DNS 垃圾/遥测过滤规则 (Junk/Telemetry)】")
    extract_rules(junk_urls, tier3_set_raw, white_set)

    # ======= 阶段 1：处理基础规则 (清理去重) =========
    write_log(">> 正在清理基础规则中的冲突和冗余内容...")
    
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

    core_sub_detect_cache = set()
    for domain in valid_core_domains:
        dot_index = domain.find('.')
        while dot_index >= 0 and dot_index < len(domain) - 1:
            core_sub_detect_cache.add(domain[dot_index + 1:])
            dot_index = domain.find('.', dot_index + 1)

    optimized_core_set = set()
    for domain in valid_core_domains:
        if domain in core_sub_detect_cache:
            continue
        optimized_core_set.add(domain)

    # ======= 阶段 2：构建防误杀保护机制 =========
    write_log(">> 正在生成重点防护名单，防止重要域名被意外拦截...")
    protected_ancestors = set()
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

    # ======= 阶段 3：过滤并合并扩展规则 (Tier 3 + Junk) =========
    write_log(">> 正在检测扩展与垃圾规则，排除与保护名单冲突的内容...")
    
    temp_tier3_valid_domains = set()
    for domain in tier3_set_raw:
        if domain in protected_ancestors:
            continue

        should_discard = False
        dot_index = domain.find('.')
        while dot_index >= 0 and dot_index < len(domain) - 1:
            parent = domain[dot_index + 1:]
            if parent in white_set:
                should_discard = True
                break
            dot_index = domain.find('.', dot_index + 1)

        if not should_discard:
            temp_tier3_valid_domains.add(domain)

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

    # ==== 阶段 4：最终合并 ====
    write_log(">> 执行两极互配互防验证并整合完成库级数据...")
    pre_combined = list(set(list(optimized_core_set) + optimized_tier3_set))
    
    global_subs_detector = set()
    for domain in pre_combined:
        dot_index = domain.find('.')
        while dot_index >= 0 and dot_index < len(domain) - 1:
            global_subs_detector.add(domain[dot_index + 1:])
            dot_index = domain.find('.', dot_index + 1)
            
    final_combined_rules = [domain for domain in pre_combined if domain not in global_subs_detector]
    final_combined_rules.sort()
    
    formatted_rules = [f"- '+.{domain}'" for domain in final_combined_rules]
    rule_count = len(formatted_rules)

    write_log("-----------------------[最终统计结果] --------------------------")
    write_log(f"[基础规则] : 初步去重后的基础拦截规则   -> 共计 : {len(optimized_core_set)} 条")
    write_log("[保护机制] : 本地白名单防误杀保护       -> 已成功生效")
    write_log(f"[扩展+垃圾] : 初步去重后的补充/DNS垃圾规则 -> 共计 : {len(optimized_tier3_set)} 条")
    write_log(f"[最终统计] : 全局防泛滥精切机制优先验并 -> 总计生成 : {rule_count} 条精准拦截源配规则段！")

    utc_time = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    generation_time = utc_time.strftime("%Y-%m-%d %H:%M:%S")

    text_content = f"""# Title: AdBlock_Rule_For_Clash
# Description: 适用于 Clash（premium 与 mihomo）的广告域名拦截 RULE-SET 规则集，包含 DNS 垃圾/遥测过滤
# Homepage: https://github.com/Filterrr/AdBlock_Rule_For_Clash
# Generated on: {generation_time} (UTC+8)
# Protected Whitelist domains Count: {len(top_whitelist)} 
# Total Payload Items Count: {rule_count}

payload:
""" + "\n".join(formatted_rules)

    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text_content)

    write_log(f">> 广告及 DNS 垃圾规则处理完成！文件保存在: {output_path}")


if __name__ == "__main__":
    main()
