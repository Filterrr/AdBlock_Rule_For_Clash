#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Title: AdBlock_Rule_For_Mihomo (Optimized v2)
# Description: 专为 Mihomo 内核优化的广告拦截规则生成脚本 - 多线程、精确子域去重、支持 IDN中文域名

import os
import re
import urllib.request
import datetime
import sys
import yaml
import concurrent.futures

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

try:
    from publicsuffixlist import PublicSuffixList
except ImportError:
    PublicSuffixList = None
    print("⚠️ 警告: 未安装 publicsuffixlist，将退回到简单的点数判断。")

custom_excluded_domains =[]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "adblock_log.txt")
SOURCES_CONFIG = os.path.join(SCRIPT_DIR, "sources.yaml")

# --- 增强型正则引擎（修复了范围提取 Bug，并完美支持 Unicode 中文域名） ---
UNICODE_CHARS = r'\u00A1-\uFFFF'
domain_regex = re.compile(rf'^(?=.{{1,253}}$)(?:(?!-)[a-zA-Z0-9.*{UNICODE_CHARS}-]{{1,63}}(?<!-)\.)+[a-zA-Z{UNICODE_CHARS}]{{2,63}}$')
regex1 = re.compile(rf'^\|\|([a-zA-Z0-9.*{UNICODE_CHARS}-]+)(?:\^.*)?$')
regex2 = re.compile(rf'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.*{UNICODE_CHARS}-]+)')
regex3 = re.compile(rf'^(?:address|server)=/([a-zA-Z0-9.*{UNICODE_CHARS}-]+)/')
regex4 = re.compile(rf'^(?:DOMAIN|HOST)(?:-SUFFIX|0WILD)?\s*,\s*([a-zA-Z0-9.*{UNICODE_CHARS}-]+\.[a-zA-Z{UNICODE_CHARS}]{{2,}})(?:\s*,.*)?$', re.IGNORECASE)
regex5 = re.compile(rf'^([a-zA-Z0-9.*{UNICODE_CHARS}-]+)$')

_psl = PublicSuffixList() if PublicSuffixList else None

def is_public_suffix(domain):
    if _psl is None: return False
    try: return _psl.is_public_suffix(domain)
    except Exception: return False

def get_registrable_domain(domain):
    if _psl is None: return None
    try: return _psl.privatesuffix(domain)
    except Exception: return None

def write_log(message):
    print(message)
    time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
        f.write(f"{time_str} - {message}\n")

def smart_decode(data):
    for encoding in ['utf-8', 'gbk', 'latin-1']:
        try: return data.decode(encoding)
        except UnicodeDecodeError: continue
    return data.decode('utf-8', errors='ignore')

def safe_read_file(file_path):
    for enc in['utf-8-sig', 'utf-8', 'gbk', 'latin-1']:
        try:
            with open(file_path, 'r', encoding=enc) as f: return f.readlines()
        except Exception: continue
    return[]

def load_sources(config_path=SOURCES_CONFIG):
    default_sources = {"allow_urls":[], "tier1_urls": [], "tier2_urls": [], "tier3_urls":[]}
    if not os.path.exists(config_path):
        write_log(f"警告: 配置文件 {config_path} 不存在，使用空订阅源")
        return default_sources
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            sources = yaml.safe_load(f)
    except Exception as e:
        write_log(f"读取配置文件失败: {e}，使用空订阅源")
        return default_sources
    for key in default_sources:
        if key not in sources or not isinstance(sources[key], list):
            sources[key] = default_sources[key]
    return sources

def parse_line_to_domain(line):
    if line.startswith("@@"): line = line[2:]
    domain = None
    if m := regex1.match(line): domain = m.group(1)
    elif m := regex2.match(line): domain = m.group(1)
    elif m := regex3.match(line): domain = m.group(1)
    elif m := regex4.match(line): domain = m.group(1)
    elif m := regex5.match(line): domain = m.group(1)
    
    if domain:
        domain = domain.strip('.')
        # 中文域名自动转 Punycode
        try:
            domain = domain.encode('idna').decode('ascii')
        except Exception:
            pass
        return domain.lower()
    return None

def fetch_single_url(url, force_whitelist=False):
    local_white, local_block = set(), set()
    skipped_psl = 0
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as response:
            content = smart_decode(response.read())
    except Exception as e:
        return url, local_white, local_block, skipped_psl, str(e)

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("!", "#", "[", ";", "//")):
            continue

        is_whitelist = force_whitelist or line.startswith("@@")
        domain = parse_line_to_domain(line)

        if domain and domain_regex.match(domain):
            if is_public_suffix(domain):
                skipped_psl += 1
                continue
            if is_whitelist:
                local_white.add(domain)
            else:
                local_block.add(domain)
                
    return url, local_white, local_block, skipped_psl, None

def extract_rules_concurrent(urls, rules_set, global_whitelist, force_whitelist=False):
    if not urls: return
    write_log(f"开始并发获取 {len(urls)} 个订阅源...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(fetch_single_url, url, force_whitelist): url for url in urls}
        for future in concurrent.futures.as_completed(futures):
            url, local_white, local_block, skipped, err = future.result()
            if err:
                write_log(f"❌ 获取失败: {url} ({err})")
            else:
                global_whitelist.update(local_white)
                rules_set.update(local_block)
                write_log(f"✅ 解析: {url} (拦截: {len(local_block)}, 白名单: {len(local_white)}, 过滤顶级域: {skipped})")

def wildcard_to_regex(domain):
    if '*' not in domain: return None
    if domain.startswith('*.') and '*' not in domain[2:]: return None
    escaped = re.escape(domain)
    return f"^{escaped.replace(r'\*', '.*')}$"

def main():
    write_log("==== 开始初始化设置 ====")
    sources = load_sources()
    white_set = set(d.lower() for d in custom_excluded_domains)
    core_set_raw, tier3_set_raw = set(), set()

    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        for line in safe_read_file(top_whitelist_file):
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", ";", "//")): continue
            domain = parse_line_to_domain(line)
            if domain and domain_regex.match(domain) and not is_public_suffix(domain):
                white_set.add(domain)

    # 启用多线程并发下载规则
    extract_rules_concurrent(sources["allow_urls"], core_set_raw, white_set, force_whitelist=True)
    extract_rules_concurrent(sources["tier1_urls"] + sources["tier2_urls"], core_set_raw, white_set)
    extract_rules_concurrent(sources["tier3_urls"], tier3_set_raw, white_set)

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

    write_log(">> 正在执行 Mihomo 域名匹配类型自动分类 (含冗余子域名精简去重)...")
    all_domains = valid_core.union(valid_tier3)

    # --- 修正后的拓扑合并核心逻辑 ---
    suffix_candidates = {d for d in all_domains if '*' not in d}
    optimized_domains = set()

    for domain in suffix_candidates:
        parts = domain.split('.')
        is_redundant = False
        for i in range(1, len(parts) - 1):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in suffix_candidates:
                is_redundant = True
                break
        if not is_redundant:
            optimized_domains.add(domain)

    for d in all_domains:
        if '*' in d: optimized_domains.add(d)

    count_wildcard = count_regex = count_exact = count_suffix = 0
    formatted_rules =[]

    for domain in sorted(optimized_domains):
        if '*' in domain:
            if domain.startswith('*.') and '*' not in domain[2:]:
                formatted_rules.append(f"- DOMAIN-WILDCARD,{domain}")
                count_wildcard += 1
            else:
                regex_pattern = wildcard_to_regex(domain)
                if regex_pattern:
                    formatted_rules.append(f"- DOMAIN-REGEX,{regex_pattern}")
                    count_regex += 1
                else:
                    formatted_rules.append(f"- DOMAIN-WILDCARD,{domain}")
                    count_wildcard += 1
            continue

        # 由于已实现子域合并，剩余非通配符规则作为 DOMAIN-SUFFIX 即可发挥最大效果
        formatted_rules.append(f"- DOMAIN-SUFFIX,{domain}")
        count_suffix += 1

    def rule_sort_key(rule):
        if rule.startswith("- DOMAIN,"): return 1
        if rule.startswith("- DOMAIN-SUFFIX,"): return 2
        if rule.startswith("- DOMAIN-WILDCARD,"): return 3
        if rule.startswith("- DOMAIN-REGEX,"): return 4
        return 99

    formatted_rules.sort(key=lambda x: (rule_sort_key(x), x))
    
    rule_count = len(formatted_rules)
    generation_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    header = f"""# Title: AdBlock_Rule_For_Mihomo (Optimized)
# Generated: {generation_time} (UTC+8)
# Total Items: {rule_count} 条
# -----------------------------------------------
# 统计信息:
# -[DOMAIN]         : {count_exact} 条
# - [DOMAIN-SUFFIX]  : {count_suffix} 条
# - [DOMAIN-WILDCARD]: {count_wildcard} 条
# -[DOMAIN-REGEX]   : {count_regex} 条
# -----------------------------------------------

payload:
"""
    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(formatted_rules))

    write_log(f"成功导出 {rule_count} 条规则至: {output_path}")

if __name__ == "__main__":
    main()
