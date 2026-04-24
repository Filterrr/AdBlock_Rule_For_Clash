#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Title: AdBlock_Rule_For_Mihomo
# Description: 专为 Mihomo 内核优化的广告拦截规则生成脚本

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
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_ad_only.conf"
]

# 目录设置
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "adblock_log.txt")

# --- 增强型正则引擎 ---
# 注意：正则不再强制要求开头是非点字符，改由代码逻辑 lstrip 处理
domain_regex = re.compile(r'^(?=.{1,253}$)(?:[a-zA-Z0-9.*-]{1,63}\.)+[a-zA-Z]{2,63}$')
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
    return []

def extract_rules(urls, rules_set, global_whitelist):
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
            
            is_whitelist = line.startswith("@@")
            if is_whitelist: line = line[2:]

            domain = None
            if m := regex1.match(line): domain = m.group(1)
            elif m := regex2.match(line): domain = m.group(1)
            elif m := regex3.match(line): domain = m.group(1)
            elif m := regex4.match(line): domain = m.group(1)
            elif m := regex5.match(line): domain = m.group(1)

            if domain:
                # 关键修复：先去掉可能存在的开头的点，防止正则失败和双重前缀
                domain = domain.lstrip('.').lower()
                if domain_regex.match(domain):
                    if is_whitelist: global_whitelist.add(domain)
                    else: rules_set.add(domain)

def main():
    write_log("==== 开始初始化设置 ====")
    white_set = set(d.lower().lstrip('.') for d in custom_excluded_domains)
    core_set_raw, tier3_set_raw = set(), set()

    # 加载本地白名单
    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        for line in safe_read_file(top_whitelist_file):
            d = line.strip().lstrip('.')
            if d and not d.startswith("#"): white_set.add(d.lower())

    # 获取规则
    extract_rules(allow_urls, core_set_raw, white_set)
    extract_rules(tier1_urls + tier2_urls, core_set_raw, white_set)
    extract_rules(tier3_urls, tier3_set_raw, white_set)

    write_log(">> 正在执行冲突清洗与保护机制校验...")
    valid_core = {d for d in core_set_raw if d not in white_set}
    
    # 构建父级保护伞
    protected_ancestors = set()
    for s in (white_set, valid_core):
        for item in s:
            if '*' in item: continue
            curr = item
            protected_ancestors.add(curr)
            while '.' in curr:
                curr = curr[curr.find('.')+1:]
                protected_ancestors.add(curr)

    # 过滤 Tier 3
    valid_tier3 = set()
    for d in tier3_set_raw:
        if d in protected_ancestors or '*' in d: 
            if '*' in d: valid_tier3.add(d)
            continue
        valid_tier3.add(d)

    # 阶段 4：Mihomo 格式智能转换
    write_log(">> 正在按照主域名 (.) 与 子域名 (+) 格式进行自动分类...")
    all_domains = valid_core.union(valid_tier3)
    
    # 后缀去重逻辑
    suffix_candidates = {d for d in all_domains if '*' not in d}
    global_subs_detector = set()
    for d in suffix_candidates:
        temp = d
        while '.' in temp:
            temp = temp[temp.find('.')+1:]
            global_subs_detector.add(temp)
    
    optimized_domains = [d for d in all_domains if d not in global_subs_detector]
    
    formatted_rules = []
    for domain in sorted(optimized_domains):
        # 情况 1: 通配符匹配 (如 *.ads.com)
        if '*' in domain:
            formatted_rules.append(f"- '{domain}'")
            continue
        
        # 情况 2: 主域名识别 (逻辑：仅含 1 个 '.'，如 baidu.com)
        if domain.count('.') == 1:
            formatted_rules.append(f"- '.{domain}'")
        
        # 情况 3: 剩余域名（多级子域名或带点的特殊规则）
        # 这里统一添加 '+.'，因为 domain 变量已经被 lstrip('.') 清理过了
        else:
            formatted_rules.append(f"- '+.{domain}'")

    # 输出文件
    rule_count = len(formatted_rules)
    generation_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    
    header = f"""# Title: AdBlock_Rule_For_Mihomo
# Generated: {generation_time} (UTC+8)
# Total Items: {rule_count}
# Formats: Main Domain ('.domain'), Subdomain ('+.domain'), Wildcard ('*.domain')

payload:
"""
    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(formatted_rules))

    write_log(f"成功导出 {rule_count} 条规则至: {output_path}")

if __name__ == "__main__":
    main()
