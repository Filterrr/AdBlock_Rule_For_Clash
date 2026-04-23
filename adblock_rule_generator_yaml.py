#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess

# ==========================================
# [关键修复 1] 强制全局输出编码为 UTF-8，防止 Windows 终端 UnicodeEncodeError
# ==========================================
if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        # 兼容旧版本 Python
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# ==========================================
# [关键修复 2] 依赖检查使用英文，避免在 cp1252 等环境崩溃
# ==========================================
try:
    import dns.resolver
except ImportError:
    # 使用英文提示，防止在不支持中文的终端抛出 UnicodeEncodeError
    print("Dependency 'dnspython' not found. Installing now...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "dnspython"], 
                              stdout=subprocess.DEVNULL, 
                              stderr=subprocess.STDOUT)
        import dns.resolver
        print("dnspython installed successfully!")
    except Exception as e:
        print(f"Failed to install dependency: {e}")
        print("Please manually run: pip install dnspython")
        sys.exit(1)

import re
import urllib.request
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# === 配置区域 ===
DNS_SERVER = '8.8.8.8'  # 指定使用 Google DNS
MAX_WORKERS = 20        # DNS 并发查询线程数

custom_excluded_domains = []

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
            write_log(f"Fetch failed {url}: {e}")

def verify_dns_effective(domain):
    """使用指定的 DNS 服务器验证域名是否有效"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [DNS_SERVER] 
    resolver.lifetime = 2.0  
    resolver.timeout = 1.0   
    try:
        resolver.resolve(domain, 'A')
        return domain 
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.exception.NoNameservers):
        return None 

def main():
    write_log(f"==== Starting [DNS {DNS_SERVER} Verification + Precise Filter] ====")
    white_set = set(d.lower() for d in custom_excluded_domains)
    raw_rules = set()

    all_urls = tier1_urls + tier2_urls + tier3_urls + junk_urls
    extract_rules(all_urls, raw_rules, white_set)
    write_log(f"Raw domains collected: {len(raw_rules)}")

    valid_set = set()
    for domain in raw_rules:
        is_whitelisted = False
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

    write_log(">> Performing precision filtering (keeping most specific subdomains)...")
    sorted_domains = sorted(list(valid_set), key=len, reverse=True)
    final_precise_set = set()
    broad_parents = set()

    for domain in sorted_domains:
        if domain in broad_parents:
            continue
        temp_dom = domain
        while True:
            idx = temp_dom.find('.')
            if idx < 0: break
            temp_dom = temp_dom[idx+1:]
            broad_parents.add(temp_dom)
        final_precise_set.add(domain)

    write_log(f"Precision filter done. Queue size: {len(final_precise_set)}")

    write_log(f">> Verifying effectiveness via {DNS_SERVER} (Multi-threaded)...")
    dns_verified_rules = []
    check_list = list(final_precise_set)
    total = len(check_list)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_domain = {executor.submit(verify_dns_effective, dom): dom for dom in check_list}
        count = 0
        for future in as_completed(future_to_domain):
            result = future.result()
            if result:
                dns_verified_rules.append(result)
            count += 1
            if count % 200 == 0:
                write_log(f"Progress: {count}/{total} ...")

    write_log(f"DNS verification complete. Effective domains: {len(dns_verified_rules)}")

    dns_verified_rules.sort()
    formatted_rules = [f"- '+.{domain}'" for domain in dns_verified_rules]
    
    utc_time = datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    generation_time = utc_time.strftime("%Y-%m-%d %H:%M:%S")

    text_content = f"""# Title: AdBlock_Rule_For_Clash_DNS_Verified
# Description: Only [DNS {DNS_SERVER} Effective] and [Most Precise] rules kept.
# Generated on: {generation_time} (UTC+8)
# Total Payload Items Count: {len(dns_verified_rules)}

payload:
""" + "\n".join(formatted_rules)

    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text_content)

    write_log(f">> Process completed! Exported {len(dns_verified_rules)} rules to: {output_path}")

if __name__ == "__main__":
    main()
