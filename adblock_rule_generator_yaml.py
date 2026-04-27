#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Title: AdBlock_Rule_For_Mihomo
# Description: 完全符合 Mihomo 内核规范的广告拦截规则生成脚本（DOMAIN-SUFFIX / DOMAIN-WILDCARD / DOMAIN-REGEX）
# 优化：保留最短有效域名（后缀覆盖）、正确处理通配符、支持正则规则提取

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
# 有效域名（允许内部通配符，但整体仍是合理域名）
domain_regex = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9.*-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')

# 传统规则提取器
regex1 = re.compile(r'^\|\|([a-zA-Z0-9.*-]+)(?:\^.*)?$')
regex2 = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.*-]+)')
regex3 = re.compile(r'^(?:address|server)=/([a-zA-Z0-9.*-]+)/')
regex4 = re.compile(r'^(?:DOMAIN|HOST)(?:-SUFFIX|-WILDCARD)?\s*,\s*([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})(?:\s*,.*)?$', re.IGNORECASE)
regex5 = re.compile(r'^([a-zA-Z0-9.*-]+)$')

# 专门提取正则规则（DOMAIN-REGEX 或直接 /regex/）
regex_regex_line = re.compile(r'^/?/.*?/?$')  # 匹配 /.../ 格式的简单正则
regex_domain_regex_prefix = re.compile(r'^DOMAIN-REGEX\s*,\s*(/.*?/)\s*(?:,.*)?$', re.IGNORECASE)

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

def parse_line_to_domain(line):
    """提取纯域名（可能包含 *）"""
    if line.startswith("@@"):
        line = line[2:]

    domain = None
    if m := regex1.match(line): domain = m.group(1)
    elif m := regex2.match(line): domain = m.group(1)
    elif m := regex3.match(line): domain = m.group(1)
    elif m := regex4.match(line): domain = m.group(1)
    elif m := regex5.match(line): domain = m.group(1)

    return domain.strip('.') if domain else None

def parse_regex_rule(line):
    """尝试提取 DOMAIN-REGEX 正则表达式，返回正则字符串或 None"""
    if line.startswith("@@"):
        line = line[2:]
    # 匹配 DOMAIN-REGEX,/regex/
    if m := regex_domain_regex_prefix.match(line):
        return m.group(1)
    # 匹配简单的 /regex/ 行
    if regex_regex_line.match(line):
        return line  # 返回整个 /regex/
    return None

def extract_rules(urls, domain_rules_set, regex_rules_set, global_whitelist, force_whitelist=False):
    """
    提取域名和正则规则
    :param force_whitelist: 若为 True，无论 @@ 前缀均视为白名单
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

            # 1. 尝试提取正则
            regex_rule = parse_regex_rule(line)
            if regex_rule:
                if is_whitelist:
                    global_whitelist.add(regex_rule)  # 正则白名单就用它本身
                else:
                    regex_rules_set.add(regex_rule)
                continue

            # 2. 提取域名
            domain = parse_line_to_domain(line)
            if domain and domain_regex.match(domain):
                domain = domain.lower()
                if is_whitelist:
                    global_whitelist.add(domain)
                else:
                    domain_rules_set.add(domain)

def main():
    write_log("==== 开始初始化设置 ====")
    white_set = set(d.lower() for d in custom_excluded_domains)

    core_domains = set()
    core_regex = set()
    tier3_domains = set()
    tier3_regex = set()

    # 加载本地白名单
    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        for line in safe_read_file(top_whitelist_file):
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                continue
            # 域名形式
            domain = parse_line_to_domain(line)
            if domain and domain_regex.match(domain):
                white_set.add(domain.lower())
            # 正则形式
            regex_rule = parse_regex_rule(line)
            if regex_rule:
                white_set.add(regex_rule)
        write_log(f"已加载本地白名单，当前白名单库共 {len(white_set)} 条。")

    # 获取规则
    extract_rules(allow_urls, core_domains, core_regex, white_set, force_whitelist=True)
    extract_rules(tier1_urls + tier2_urls, core_domains, core_regex, white_set)
    extract_rules(tier3_urls, tier3_domains, tier3_regex, white_set)

    # 阶段 1 & 2：冲突清洗（白名单移除）
    write_log(">> 正在执行冲突清洗与保护机制校验...")
    valid_core_domains = {d for d in core_domains if d not in white_set}
    valid_core_regex = {r for r in core_regex if r not in white_set}

    # 构建父级保护伞（仅针对不含 * 的普通域名）
    protected_ancestors = set()
    for item in valid_core_domains:
        if '*' in item: continue
        curr = item
        protected_ancestors.add(curr)
        while '.' in curr:
            curr = curr[curr.find('.')+1:]
            protected_ancestors.add(curr)

    # 阶段 3：过滤 Tier 3 域名
    valid_tier3_domains = set()
    for d in tier3_domains:
        if d in white_set: continue
        # 含通配符的域名直接加入，不参与保护校验
        if '*' in d:
            valid_tier3_domains.add(d)
            continue
        # 若当前域名或其任意上级域名在保护伞中，则丢弃
        covered = any(parent in protected_ancestors for parent in [d] + ['.'.join(d.split('.')[i:]) for i in range(1, d.count('.')+1)])
        if not covered:
            valid_tier3_domains.add(d)

    # Tier 3 正则直接过滤白名单
    valid_tier3_regex = {r for r in tier3_regex if r not in white_set}

    # 阶段 4：Mihomo 格式智能转换
    write_log(">> 正在执行 Mihomo 域名匹配类型自动分类...")

    # ====== 处理通配符域名 ======
    wildcard_domains = set()
    normal_domains = set()

    for domain in valid_core_domains.union(valid_tier3_domains):
        if '*' in domain:
            # 规范化为 *.example.com 形式
            clean = domain.lstrip('*').lstrip('.')
            if clean:
                wildcard_domains.add(f"*.{clean}")
        else:
            normal_domains.add(domain)

    # ====== 普通域名：最短父域名去重（后缀覆盖） ======
    sorted_normal = sorted(normal_domains, key=lambda d: d.count('.'))
    seen_parents = set()
    final_suffix_domains = set()

    for d in sorted_normal:
        parts = d.split('.')
        covered = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in seen_parents:
                covered = True
                break
        if not covered:
            seen_parents.add(d)
            final_suffix_domains.add(d)

    # ====== 最终规则生成 ======
    count_suffix = 0
    count_wildcard = 0
    count_regex = 0
    formatted_rules = []

    # DOMAIN-SUFFIX
    for domain in sorted(final_suffix_domains):
        formatted_rules.append(f"- '+.{domain}'")
        count_suffix += 1

    # DOMAIN-WILDCARD
    for domain in sorted(wildcard_domains):
        formatted_rules.append(f"- '{domain}'")
        count_wildcard += 1

    # DOMAIN-REGEX (来自 core + tier3)
    all_regex = valid_core_regex.union(valid_tier3_regex)
    for regex_rule in sorted(all_regex):
        # 确保带斜杠
        if not regex_rule.startswith('/'):
            regex_rule = '/' + regex_rule + '/'
        formatted_rules.append(f"- '{regex_rule}'")
        count_regex += 1

    # 输出文件
    rule_count = len(formatted_rules)
    generation_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")

    header = f"""# Title: AdBlock_Rule_For_Mihomo
# Generated: {generation_time} (UTC+8)
# Total Items: {rule_count} 条
# -----------------------------------------------
# 统计信息（严格遵循 Mihomo 语法）:
# - [DOMAIN-SUFFIX  ] (+.) : {count_suffix} 条
# - [DOMAIN-WILDCARD] (*.) : {count_wildcard} 条
# - [DOMAIN-REGEX   ] (/…/) : {count_regex} 条
# - [DOMAIN-KEYWORD ]      : 0 条（未从规则源提取）
# - [DOMAIN         ]      : 0 条（已用后缀覆盖，无需精确）
# -----------------------------------------------

payload:
"""
    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(formatted_rules))

    write_log(f"成功导出 {rule_count} 条规则至: {output_path}")

if __name__ == "__main__":
    main()
