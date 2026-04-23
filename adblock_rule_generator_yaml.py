#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import urllib.request
import datetime
import sys
import asyncio
from dns.asyncresolver import Resolver

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# === 自定义白名单 ===
custom_excluded_domains = []

# === 规则源 ===
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

# ================= 工具函数 =================

domain_regex = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')

def extract_rules(urls, rules_set):
    for url in urls:
        try:
            content = urllib.request.urlopen(url, timeout=20).read().decode('utf-8', 'ignore')
        except:
            continue

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("!", "#")):
                continue

            if line.startswith("||"):
                domain = line[2:].split("^")[0]
            else:
                domain = line

            if domain_regex.match(domain):
                rules_set.add(domain.lower())

# ================= DNS 模块 =================

class DNSFilter:
    def __init__(self, nameservers=None, concurrency=200):
        self.resolver = Resolver()
        self.resolver.nameservers = nameservers or ["127.0.0.1"]
        self.resolver.lifetime = 2
        self.sem = asyncio.Semaphore(concurrency)
        self.cache = {}

    async def _resolve(self, domain):
        if domain in self.cache:
            return domain, self.cache[domain]

        async with self.sem:
            try:
                ans = await self.resolver.resolve(domain, "A")
                ips = [str(r) for r in ans]
            except:
                ips = []

        self.cache[domain] = ips
        return domain, ips

    async def resolve_all(self, domains):
        tasks = [self._resolve(d) for d in domains]
        result = await asyncio.gather(*tasks)
        return dict(result)

def dns_filter(domains, dns_map, whitelist):
    result = set()
    for d in domains:
        if d in whitelist:
            result.add(d)
            continue

        ips = dns_map.get(d, [])
        if not ips:
            continue
        if any(ip in ("0.0.0.0", "127.0.0.1") for ip in ips):
            continue

        result.add(d)
    return result

# ================= 父子域去重 =================

def remove_parent(domains):
    sub = set()
    for d in domains:
        i = d.find('.')
        while i != -1:
            sub.add(d[i+1:])
            i = d.find('.', i+1)
    return {d for d in domains if d not in sub}

# ================= 主逻辑 =================

def main():
    white_set = set(custom_excluded_domains)

    core_raw = set()
    tier3_raw = set()

    print("获取核心规则...")
    extract_rules(tier1_urls + tier2_urls, core_raw)

    print("获取扩展规则...")
    extract_rules(tier3_urls, tier3_raw)

    # ===== 核心规则处理 =====
    core_clean = {d for d in core_raw if d not in white_set}
    core_final = remove_parent(core_clean)

    # ===== Tier3 DNS过滤 =====
    print("DNS过滤 Tier3...")
    dnsf = DNSFilter()

    loop = asyncio.get_event_loop()
    dns_map = loop.run_until_complete(dnsf.resolve_all(tier3_raw))

    tier3_filtered = dns_filter(tier3_raw, dns_map, white_set)
    tier3_final = remove_parent(tier3_filtered)

    # ===== 合并 =====
    final = remove_parent(core_final | tier3_final)
    final = sorted(final)

    # ===== 输出 =====
    out = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")

    with open(out, "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for d in final:
            f.write(f"- '+.{d}'\n")

    print("完成:", len(final))

if __name__ == "__main__":
    main()
