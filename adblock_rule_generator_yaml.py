#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import urllib.request
import datetime
import sys
import socket  # 用于 DNS 验证

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# === 自定义全局白名单 ===
custom_excluded_domains = []

# === 订阅源 ===
allow_urls = []
tier1_urls = [
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
]
tier2_urls = [
    "https://easylist-downloads.adblockplus.org/easylistchina.txt",
    "https://easylist-downloads.adblockplus.org/easylist.txt"
]
tier3_urls = [
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",
]
junk_urls = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "adblock_log.txt")

def write_log(message):
    print(message)
    time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
        f.write(f"{time_str} - {message}\n")

# 正则引擎
domain_regex = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')
regex1 = re.compile(r'^\|\|((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?:\^.*)?$')
regex2 = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.-]+)')
regex3 = re.compile(r'^(?:address|server)=/([a-zA-Z0-9.-]+)/')
regex4 = re.compile(r'^(?:DOMAIN|HOST)(?:-SUFFIX)?\s*,\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:\s*,.*)?$', re.IGNORECASE)
regex5 = re.compile(r'^([a-zA-Z0-9.-]+)$')

def extract_rules(urls, rules_set, global_whitelist):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"}
    for url in urls:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read().decode('utf-8', errors='ignore')
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith(("!", "#", "[", ";", "//")): continue
                    is_whitelist = line.startswith("@@")
                    if is_whitelist: line = line[2:]
                    domain = None
                    if m := regex1.match(line): domain = m.group(1)
                    elif m := regex2.match(line): domain = m.group(1)
                    elif m := regex3.match(line): domain = m.group(1)
                    elif m := regex4.match(line): domain = m.group(1)
                    elif m := regex5.match(line): domain = m.group(1)
                    if domain and domain_regex.match(domain):
                        domain = domain.lower()
                        if is_whitelist: global_whitelist.add(domain)
                        else: rules_set.add(domain)
        except Exception as e:
            write_log(f"获取失败 {url}: {e}")

def verify_dns_effective(domain):
    """验证域名是否在 DNS 中真实有效 (可解析)"""
    try:
        # 设置全局 DNS 超时，防止卡死
        socket.setdefaulttimeout(1) 
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, socket.timeout):
        return False

def main():
    write_log("==== 开始执行 [DNS 验证 + 精准过滤] 模式 ====")
    white_set = set(d.lower() for d in custom_excluded_domains)
    raw_rules = set()

    # 1. 收集所有规则
    all_urls = tier1_urls + tier2_urls + tier3_urls + junk_urls
    extract_rules(all_urls, raw_rules, white_set)
    write_log(f"初步收集到原始域名: {len(raw_rules)} 条")

    # 2. 排除白名单及其子域
    valid_set = set()
    for domain in raw_rules:
        is_whitelisted = False
        # 检查该域名或其任何父级是否在白名单中
        temp_dom = domain
        while True:
            if temp_dom in white_set:
                is_whitelisted = True
                break
            idx = temp_dom.find('.')
            if idx < 0: break
            temp_dom = temp_dom[idx+1:]
        if not is_whitelisted:
            valid_set.add(domain)

    # 3. 【核心：精准度过滤】- 只保留最深层的子域
    write_log(">> 正在执行精准度筛选 (剔除宽泛根域，保留具体子域)...")
    # 将所有域名按长度降序排列（长域名优先处理，即最精准的优先）
    sorted_domains = sorted(list(valid_set), key=len, reverse=True)
    final_precise_set = set()
    broad_parents = set()

    for domain in sorted_domains:
        # 如果该域名已经是某个已保留精准域名的父级，则剔除该域名
        if any(domain == p for p in broad_parents):
            continue
        
        # 记录该域名的所有父级，防止后续处理到父级时将其加入
        temp_dom = domain
        while True:
            idx = temp_dom.find('.')
            if idx < 0: break
            temp_dom = temp_dom[idx+1:]
            broad_parents.add(temp_dom)
            
        final_precise_set.add(domain)

    write_log(f"精准度筛选完成，剩余 {len(final_precise_set)} 条")

    # 4. 【核心：DNS 有效性验证】
    write_log(">> 正在通过 DNS 验证域名有效性 (此步骤较慢，请耐心等待)...")
    dns_verified_rules = []
    total = len(final_precise_set)
    
    # 将集合转为列表以便跟踪进度
    check_list = list(final_precise_set)
    for i, domain in enumerate(check_list):
        if i % 100 == 0:
            write_log(f"进度: {i}/{total} ...")
        
        if verify_dns_effective(domain):
            dns_verified_rules.append(domain)

    write_log(f"DNS 验证完成，有效域名共: {len(dns_verified_rules)} 条")

    # 5. 导出文件
    dns_verified_rules.sort()
    formatted_rules = [f"- '+.{domain}'" for domain in dns_verified_rules]
    
    utc_time = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    generation_time = utc_time.strftime("%Y-%m-%d %H:%M:%S")

    text_content = f"""# Title: AdBlock_Rule_For_Clash_DNS_Verified
# Description: 仅保留 [DNS有效] 且 [最精准] 的拦截规则
# Generated on: {generation_time} (UTC+8)
# Total Payload Items Count: {len(dns_verified_rules)}

payload:
""" + "\n".join(formatted_rules)

    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text_content)

    write_log(f">> 处理完成！最终导出精准有效规则: {len(dns_verified_rules)} 条")

if __name__ == "__main__":
    main()
