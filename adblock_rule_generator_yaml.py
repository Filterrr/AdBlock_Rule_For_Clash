#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Title: AdBlock_Rule_For_Mihomo
# Description: 专为 Mihomo 内核优化的广告拦截规则生成脚本
# 功能：自动识别域名特征，智能分配 DOMAIN, DOMAIN-WILDCARD, DOMAIN-SUFFIX 与 DOMAIN-REGEX 匹配格式。

import os
import re
import urllib.request
import datetime
import sys

# 强制标准输出为 UTF-8
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# === 自定义全局白名单 ===
custom_excluded_domains = [
    # "example.com",
]

# === 订阅源配置 ===
allow_urls = [
    "https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/white.txt"
]

tier1_urls = [
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt"
]

tier2_urls = [
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_104_EasyListChina/filter.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/thirdparties/easylist/easylist.txt"
]

tier3_urls = [
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://anti-ad.net/adguard.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-general.txt"
]

# 目录设置
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "adblock_log.txt")

# --- 增强型正则引擎 ---
domain_regex = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9.*-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')
regex1 = re.compile(r'^\|\|([a-zA-Z0-9.*-]+)(?:\^.*)?$')
regex2 = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.*-]+)')
regex3 = re.compile(r'^(?:address|server)=/([a-zA-Z0-9.*-]+)/')
regex4 = re.compile(r'^(?:DOMAIN|HOST)(?:-SUFFIX|0WILD)?\s*,\s*([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})(?:\s*,.*)?$', re.IGNORECASE)
regex5 = re.compile(r'^([a-zA-Z0-9.*-]+)$')
# 新增：用于匹配 Adblock 语法中被 / 包裹的正则规则 (例如 /^abc.*com/)
regex_adblock_regex = re.compile(r'^/(.+)/$')

def write_log(message):
    print(message)
    time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
        f.write(f"{time_str} - {message}\n")

def smart_decode(data):
    for encoding in ['utf-8', 'gbk', 'latin-1']:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode('utf-8', errors='ignore')

def safe_read_file(file_path):
    encodings = ['utf-8-sig', 'utf-8', 'gbk', 'latin-1']
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                return f.readlines()
        except Exception:
            continue
    return []

# --- 通用提取器 ---
def parse_line_to_domain_or_regex(line):
    """提取域名或纯正则表达式，返回 (类型, 值)"""
    if line.startswith("@@"): 
        line = line[2:]
    
    # 优先检测是否为纯正则规则 (例如 /regex/)
    if m := regex_adblock_regex.match(line):
        return 'regex', m.group(1)
        
    domain = None
    if m := regex1.match(line): domain = m.group(1)
    elif m := regex2.match(line): domain = m.group(1)
    elif m := regex3.match(line): domain = m.group(1)
    elif m := regex4.match(line): domain = m.group(1)
    elif m := regex5.match(line): domain = m.group(1)

    if domain:
        return 'domain', domain.strip('.')
    return None, None

def extract_rules(urls, domain_set, regex_set, global_whitelist, force_whitelist=False):
    """
    提取规则
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    for url in urls:
        write_log(f"正在获取: {url}")
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                content = smart_decode(response.read())
        except Exception as e:
            write_log(f"获取失败: {e}")
            continue

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                continue
            
            is_whitelist = force_whitelist or line.startswith("@@")
            
            # 使用提取器判断是正则还是域名
            rule_type, rule_value = parse_line_to_domain_or_regex(line)

            if rule_type == 'regex':
                if not is_whitelist: # 暂不处理正则白名单，防止误伤
                    regex_set.add(rule_value)
            elif rule_type == 'domain' and domain_regex.match(rule_value):
                rule_value = rule_value.lower()
                if is_whitelist: 
                    global_whitelist.add(rule_value)
                else: 
                    domain_set.add(rule_value)

def main():
    write_log("==== 开始初始化设置 ====")
    white_set = set(d.lower() for d in custom_excluded_domains)
    core_set_raw, tier3_set_raw = set(), set()
    regex_rules_raw = set() # 新增正则规则存储容器

    # 加载本地高权重白名单
    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        for line in safe_read_file(top_whitelist_file):
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                continue
            
            rule_type, rule_value = parse_line_to_domain_or_regex(line)
            if rule_type == 'domain' and domain_regex.match(rule_value):
                white_set.add(rule_value.lower())
        write_log(f"已加载本地白名单，当前白名单库共 {len(white_set)} 条。")

    # 获取规则 
    extract_rules(allow_urls, core_set_raw, regex_rules_raw, white_set, force_whitelist=True)
    extract_rules(tier1_urls + tier2_urls, core_set_raw, regex_rules_raw, white_set)
    extract_rules(tier3_urls, tier3_set_raw, regex_rules_raw, white_set)

    # 阶段 1 & 2：预处理与冲突检测 (仅针对普通域名)
    write_log(">> 正在执行冲突清洗与保护机制校验...")
    valid_core = {d for d in core_set_raw if d not in white_set}
    
    protected_ancestors = set()
    for s in (white_set, valid_core):
        for item in s:
            if '*' in item: continue
            curr = item
            protected_ancestors.add(curr)
            while '.' in curr:
                curr = curr[curr.find('.')+1:]
                protected_ancestors.add(curr)

    # 阶段 3：过滤 Tier 3
    valid_tier3 = set()
    for d in tier3_set_raw:
        if d in protected_ancestors or '*' in d: 
            if '*' in d: valid_tier3.add(d)
            continue
        valid_tier3.add(d)

    # 阶段 4：Mihomo 格式智能转换
    write_log(">> 正在执行 Mihomo 域名匹配类型自动分类...")
    all_domains = valid_core.union(valid_tier3)
    
    suffix_candidates = {d for d in all_domains if '*' not in d}
    global_subs_detector = set()
    for d in suffix_candidates:
        temp = d
        while '.' in temp:
            temp = temp[temp.find('.')+1:]
            global_subs_detector.add(temp)
    
    optimized_domains = [d for d in all_domains if d not in global_subs_detector]
    
    # --- 新增计数器 ---
    count_wildcard = 0
    count_exact = 0
    count_suffix = 0
    count_regex = 0
    
    formatted_rules = []
    
    # 优先写入正则规则 (DOMAIN-REGEX)
    for regex_rule in sorted(regex_rules_raw):
        # 简单清洗，防止空正则
        if len(regex_rule) > 2: 
            formatted_rules.append(f"- DOMAIN-REGEX,{regex_rule}")
            count_regex += 1

    # 写入常规路由规则
    for domain in sorted(optimized_domains):
        if '*' in domain:
            formatted_rules.append(f"- DOMAIN-WILDCARD,{domain}")
            count_wildcard += 1
            continue
        
        if domain.count('.') >= 2:
            formatted_rules.append(f"- DOMAIN,{domain}")
            count_exact += 1
            continue
        
        formatted_rules.append(f"- DOMAIN-SUFFIX,{domain}")
        count_suffix += 1

    # 输出文件
    rule_count = len(formatted_rules)
    generation_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    
    # 在 Header 中添加正则统计信息
    header = f"""# Title: AdBlock_Rule_For_Mihomo
# Generated: {generation_time} (UTC+8)
# Total Items: {rule_count} 条
# -----------------------------------------------
# 统计分类信息:
# - [正则匹配 ] (DOMAIN-REGEX)    : {count_regex} 条
# - [通配符匹配] (DOMAIN-WILDCARD) : {count_wildcard} 条
# - [精准匹配 ] (DOMAIN)          : {count_exact} 条
# - [后缀匹配 ] (DOMAIN-SUFFIX)   : {count_suffix} 条
# -----------------------------------------------

payload:
"""
    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(formatted_rules))

    write_log(f"成功导出 {rule_count} 条规则至: {output_path}")

if __name__ == "__main__":
    main()
