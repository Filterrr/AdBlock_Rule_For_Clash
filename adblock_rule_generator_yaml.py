#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Title: AdBlock_Rule_For_Mihomo
# Description: 专为 Mihomo 内核优化的广告拦截规则生成脚本
# 功能：根据 AdGuard 语法结构，智能分配精确、单级通配、纯子域与完整泛域名匹配格式。

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
allow_urls =[
    "https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/white.txt"
]

tier1_urls =[
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt"
]

tier2_urls =[
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylist.txt"
]

tier3_urls =[
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_ad_only.conf"
]

# 目录设置
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "adblock_log.txt")

# --- 增强型正则引擎：支持通配符 (*) 提取 ---
domain_regex = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9.*-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')
regex1 = re.compile(r'^\|\|([a-zA-Z0-9.*-]+)(?:\^.*)?$')
regex2 = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.*-]+)')
regex3 = re.compile(r'^(?:address|server)=/([a-zA-Z0-9.*-]+)/')
regex4 = re.compile(r'^(?:DOMAIN|HOST)(?:-SUFFIX|0WILD)?\s*,\s*([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})(?:\s*,.*)?$', re.IGNORECASE)
regex5 = re.compile(r'^([a-zA-Z0-9.*-]+)$')

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
    return[]

# --- 通用域名提取器 ---
def parse_line_to_domain(line):
    """统一使用正则提取域名，兼容各种规则格式"""
    if line.startswith("@@"): 
        line = line[2:]
    
    if m := regex1.match(line): return m.group(1)
    if m := regex2.match(line): return m.group(1)
    if m := regex3.match(line): return m.group(1)
    if m := regex4.match(line): return m.group(1)
    if m := regex5.match(line): return m.group(1)
    return None

def extract_rules(urls, rules_set, global_whitelist, force_whitelist=False):
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
            domain = parse_line_to_domain(line)

            if domain and domain_regex.match(domain):
                domain = domain.lower()
                if is_whitelist: 
                    global_whitelist.add(domain)
                else: 
                    rules_set.add(domain)

def main():
    write_log("==== 开始初始化设置 ====")
    white_set = set(d.lower() for d in custom_excluded_domains)
    core_set_raw, tier3_set_raw = set(), set()

    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        for line in safe_read_file(top_whitelist_file):
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                continue
            domain = parse_line_to_domain(line)
            if domain and domain_regex.match(domain):
                white_set.add(domain.lower())
        write_log(f"已加载本地白名单，当前库共 {len(white_set)} 条。")

    extract_rules(allow_urls, core_set_raw, white_set, force_whitelist=True)
    extract_rules(tier1_urls + tier2_urls, core_set_raw, white_set)
    extract_rules(tier3_urls, tier3_set_raw, white_set)

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

    valid_tier3 = set()
    for d in tier3_set_raw:
        if d in protected_ancestors or '*' in d: 
            if '*' in d: valid_tier3.add(d) 
            continue
        valid_tier3.add(d)

    write_log(">> 正在执行 Mihomo 域名匹配类型自动分类...")
    all_domains = valid_core.union(valid_tier3)
    
    # 剔除已被父域名覆盖的子域名（只对非通配符运算）
    suffix_candidates = {d for d in all_domains if '*' not in d}
    global_subs_detector = set()
    for d in suffix_candidates:
        temp = d
        while '.' in temp:
            temp = temp[temp.find('.')+1:]
            global_subs_detector.add(temp)
    
    optimized_domains =[d for d in all_domains if d not in global_subs_detector]
    
    # --- 新增统计计数器 ---
    count_full_suffix = 0   # +.domain.com
    count_sub_only = 0      # .example.com
    count_wildcard = 0      # *.*.example.com
    count_exact = 0         # exact.example.com
    
    formatted_rules =[]
    for domain in sorted(optimized_domains):
        
        # 1. 纯子域匹配 (如 AdGuard 提取出来的 *.example.com)
        # Mihomo 特性: '.example.com' 匹配多级，但不匹配根域名 example.com
        if domain.startswith('*.'):
            base_domain = domain[2:] # 剥离 *.
            formatted_rules.append(f"- '.{base_domain}'")
            count_sub_only += 1
            continue
            
        # 2. 单级/多位置通配符匹配 (如 sub.*.example.com)
        # Mihomo 特性: '*' 一次只能匹配一级域名，不支持跨级匹配
        if '*' in domain:
            formatted_rules.append(f"- '{domain}'")
            count_wildcard += 1
            continue
        
        # 3. 精准匹配 (层级 >= 3 的一般对应特定服务器或 API，如 ads.m.itunes.apple.com)
        # Mihomo 特性: 'books.itunes.example.com' 直接精准匹配，防误杀父域名
        if domain.count('.') >= 3:
            formatted_rules.append(f"- '{domain}'")
            count_exact += 1
            continue
        
        # 4. 根域泛域名匹配 (如 AdGuard 的 ||example.com^)
        # Mihomo 特性: '+.example.com' 既能匹配多级子域，也能匹配根域名 example.com
        formatted_rules.append(f"- '+.{domain}'")
        count_full_suffix += 1

    rule_count = len(formatted_rules)
    generation_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    
    header = f"""# Title: AdBlock_Rule_For_Mihomo
# Generated: {generation_time} (UTC+8)
# Total Items: {rule_count} 条规则
# -----------------------------------------------
# 规则格式统计信息 (基于 Mihomo 特性解析):
# - [完整泛匹配] (+.domain.com)      : {count_full_suffix} 条 (匹配多级及根域名)
# - [纯子域匹配] (.example.com)      : {count_sub_only} 条 (匹配多级，不匹配根)
# - [精准匹配  ] (exact.example.com) : {count_exact} 条 (直接比对)
# - [单级通配符] (*.*.example.com)   : {count_wildcard} 条 (*仅限匹配单层)
# -----------------------------------------------

payload:
"""
    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(formatted_rules))

    write_log(f"成功导出 {rule_count} 条规则至: {output_path}")

if __name__ == "__main__":
    main()
