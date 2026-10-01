#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Title: AdBlock_Rule_For_Mihomo
# Description: 专为 Mihomo 内核优化的广告拦截规则生成脚本（TXT 输出）

import os
import re
import urllib.request
import datetime
import sys
import yaml

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

custom_excluded_domains = []

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "adblock_log.txt")
SOURCES_CONFIG = os.path.join(SCRIPT_DIR, "sources.yaml")

domain_regex = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9.*-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')
regex1 = re.compile(r'^\|\|([a-zA-Z0-9.*-]+)(?:\^.*)?$')
regex2 = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.*-]+)')
regex3 = re.compile(r'^(?:address|server)=/([a-zA-Z0-9.*-]+)/')
regex4 = re.compile(r'^(?:DOMAIN|HOST)(?:-SUFFIX|0WILD)?\s*,\s*([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})(?:\s*,.*)?$', re.IGNORECASE)
regex5 = re.compile(r'^([a-zA-Z0-9.*-]+)$')

# --- 尝试导入 publicsuffixlist ---
try:
    from publicsuffixlist import PublicSuffixList
except ImportError:
    PublicSuffixList = None
    print("⚠️ 警告: 未安装 publicsuffixlist，将退回到简单的点数判断。")
    print("    (建议执行: pip install publicsuffixlist)")

_psl = PublicSuffixList() if PublicSuffixList else None

def is_public_suffix(domain):
    """检查域名是否为公共后缀 (如 'com', 'co.uk')，若是则返回 True"""
    if _psl is None:
        return False
    try:
        return _psl.is_public_suffix(domain)
    except Exception:
        return False

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

def load_sources(config_path=SOURCES_CONFIG):
    default_sources = {"allow_urls": [], "tier1_urls": [], "tier2_urls": [], "tier3_urls": [], "tier4_urls": []}
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
    if line.startswith("@@"):
        line = line[2:]
    domain = None
    if m := regex1.match(line): domain = m.group(1)
    elif m := regex2.match(line): domain = m.group(1)
    elif m := regex3.match(line): domain = m.group(1)
    elif m := regex4.match(line): domain = m.group(1)
    elif m := regex5.match(line): domain = m.group(1)
    return domain.strip('.') if domain else None

def is_global_exception(line: str) -> bool:
    """
    判断 @@ 行是否为『真·全局白名单』。
    只有无任何修饰符、无 URL 级内容的 @@ 规则才是全局豁免；
    带 $domain= / $generichide 等修饰符或 URL 参数的豁免是站点/资源级，
    不应作为全局白名单（否则会错误放行大量广告域）。
    """
    if '$' in line:
        return False
    core = line[2:] if line.startswith('@@') else line
    if re.match(r'^\|\|([a-zA-Z0-9.*-]+)\^(.+)$', core):
        return False
    if core.startswith('||'):
        rest = core[2:]
        if '/' in rest:
            return False
        return True
    if '/' in core:
        return False
    return True

# --- 可安全收编的资源修饰符（无 domain= 时语义等价于该域全局拦截） ---
ADOPTABLE_MODIFIERS = {'third-party', 'all', 'document', 'important'}

def parse_block_rule(line: str) -> str | None:
    """
    解析『拦截规则』，只返回【无条件全局域名拦截】意图的域名。
    带 $domain= 的站点级限制、带资源类型的条件性限制一律不提取，
    避免把"某站点限制"误读为"全网络封禁"。
    """
    m = re.match(r'^\|\|([a-zA-Z0-9.*-]+)(.*)$', line)
    if m:
        dom, rest = m.group(1), m.group(2)
        if rest == '' or rest == '^':
            if dom.startswith('*.'):
                dom = dom[2:]
            return dom.strip('.').lower() or None
        if rest.startswith('^$'):
            mods = [s.strip() for s in rest[2:].split(',')]
            if mods and all(m in ADOPTABLE_MODIFIERS for m in mods):
                if dom.startswith('*.'):
                    dom = dom[2:]
                return dom.strip('.').lower() or None
            return None
        return None

    m = regex2.match(line)
    if m:
        return m.group(1).strip('.').lower() or None

    m = regex3.match(line)
    if m:
        return m.group(1).strip('.').lower() or None

    m = regex4.match(line)
    if m:
        return m.group(1).strip('.').lower() or None

    token = line
    if token.startswith('*.'):
        token = token[2:]
    if re.match(r'^[a-zA-Z0-9.*-]+$', token) and '$' not in token and '.' in token:
        return token.strip('.').lower() or None

    return None

def extract_rules(urls, rules_set, global_whitelist, force_whitelist=False, curated_white=None):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    total_blocked = 0
    total_whitelisted = 0
    total_filtered = 0

    for url in urls:
        blocked = 0
        whitelisted = 0
        filtered_tld = 0
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

            # ★ 白名单行：仅收『真·全局豁免』
            if line.startswith('@@'):
                if is_global_exception(line):
                    domain = parse_line_to_domain(line)
                    if domain and domain_regex.match(domain):
                        domain = domain.lower()
                        if is_public_suffix(domain):
                            filtered_tld += 1
                            continue
                        global_whitelist.add(domain)
                        whitelisted += 1
                continue

            if force_whitelist:
                domain = parse_line_to_domain(line)
                if domain and domain_regex.match(domain):
                    domain = domain.lower()
                    if is_public_suffix(domain):
                        filtered_tld += 1
                        continue
                    global_whitelist.add(domain)
                    whitelisted += 1
                    # ★ 记录人工维护的功能性白名单（用于父域降级保护/白名单产物）
                    if curated_white is not None:
                        curated_white.add(domain)
                continue

            # ★ 拦截行：仅收『无条件全局域名拦截』
            domain = parse_block_rule(line)
            if domain and domain_regex.match(domain):
                domain = domain.lower()
                if is_public_suffix(domain):
                    filtered_tld += 1
                    continue
                rules_set.add(domain)
                blocked += 1

        print(f"✔ 解析: {url} (拦截: {blocked}, 白名单: {whitelisted}, 过滤顶级域: {filtered_tld})")
        total_blocked += blocked
        total_whitelisted += whitelisted
        total_filtered += filtered_tld

    return total_blocked, total_whitelisted, total_filtered

def main():
    write_log("==== 开始初始化设置 ====")
    sources = load_sources()
    allow_urls = sources["allow_urls"]
    tier1_urls = sources["tier1_urls"]
    tier2_urls = sources["tier2_urls"]
    tier3_urls = sources["tier3_urls"]
    tier4_urls = sources["tier4_urls"]

    white_set = set(d.lower() for d in custom_excluded_domains)
    curated_white = set()  # ★ 人工维护的功能性白名单（需要父域级保护）
    core_set_raw, tier3_set_raw = set(), set()

    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        for line in safe_read_file(top_whitelist_file):
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                continue
            domain = parse_line_to_domain(line)
            if domain and domain_regex.match(domain):
                if not is_public_suffix(domain):
                    white_set.add(domain.lower())
        write_log(f"已加载本地白名单，当前白名单库共 {len(white_set)} 条。")

    final_blocked = 0
    final_whitelisted = 0
    final_filtered_tld = 0

    if allow_urls:
        print(f"开始并获取 {len(allow_urls)} 个订阅源...")
        b, w, f = extract_rules(allow_urls, core_set_raw, white_set, force_whitelist=True, curated_white=curated_white)
        final_blocked += b
        final_whitelisted += w
        final_filtered_tld += f

    tier12 = tier1_urls + tier2_urls
    if tier12:
        print(f"开始并获取 {len(tier12)} 个订阅源...")
        b, w, f = extract_rules(tier12, core_set_raw, white_set)
        final_blocked += b
        final_whitelisted += w
        final_filtered_tld += f

    tier34 = tier3_urls + tier4_urls
    if tier34:
        print(f"开始并获取 {len(tier34)} 个订阅源...")
        b, w, f = extract_rules(tier34, tier3_set_raw, white_set)
        final_blocked += b
        final_whitelisted += w
        final_filtered_tld += f

    write_log(">> 正在执行冲突清洗与保护机制校验...")

    # 白名单保护：只剔除『白名单本体及其子域』（精确剔除，不做祖先保护，
    # 避免因个别白名单例外而误删整个广告根域）
    def under_whitelist(d):
        if d in white_set:
            return True
        parts = d.split('.')
        for i in range(1, len(parts)):
            if '.'.join(parts[i:]) in white_set:
                return True
        return False

    valid_core = {d for d in core_set_raw if not under_whitelist(d)}
    valid_tier3 = {d for d in tier3_set_raw if not under_whitelist(d)}

    write_log(">> 正在执行 Mihomo 域名匹配类型自动分类...")
    all_domains = valid_core.union(valid_tier3)

    # ★ 修复去重方向：父域存在时删除其子域（DOMAIN-SUFFIX 语义下父域已覆盖子域）
    suffix_candidates = {d for d in all_domains if '*' not in d}

    def has_ancestor_in(domain, domain_pool):
        parts = domain.split('.')
        for i in range(1, len(parts)):
            if '.'.join(parts[i:]) in domain_pool:
                return True
        return False

    optimized_domains = {d for d in suffix_candidates if not has_ancestor_in(d, suffix_candidates)}

    count_wildcard = 0
    count_suffix = 0
    formatted_rules = []

    # ★ TXT 输出修正：生成纯文本行（`+.domain` 为 mihomo trie 语法的后缀匹配写法），
    # 不再输出 YAML payload 语法（'- '+.domain''），
    # 这样可直接用于 rule-provider 的 behavior: domain + format: text。
    for domain in sorted(optimized_domains):
        formatted_rules.append(f"+.{domain}")
        count_suffix += 1

    rule_count = len(formatted_rules)
    generation_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    header = f"""# Title: AdBlock_Rule_For_Mihomo
# Generated: {generation_time} (UTC+8)
# Total Items: {rule_count} 条
# -----------------------------------------------
# 统计信息:
# - [后缀匹配] (+.a.com)     : {count_suffix} 条
# -----------------------------------------------
# 说明: 本文件为纯文本规则集，配套配置:
#   rule-providers:
#     adblock:
#       type: http
#       behavior: domain
#       format: text
#       url: <本文件地址>
#   rules:
#     - RULE-SET,adblock,REJECT
# -----------------------------------------------

"""
    # ★ 以二进制模式写入，确保 LF 行尾（Windows 文本模式会把 \n 写成 \r\n）
    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.txt")
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(header + "\n".join(formatted_rules))

    # ★ 额外产物：功能性白名单纯文本规则集（adblock_allow.txt）
    # 用法: 在主拦截规则之前引用 → RULE-SET,adblock-allow,DIRECT
    allow_lines = []
    for d in sorted(white_set):
        if is_public_suffix(d):
            continue
        allow_lines.append(f"+.{d}")
    allow_header = f"""# Title: AdBlock_Rule_For_Mihomo (Allowlist)
# Generated: {generation_time} (UTC+8)
# Total Items: {len(allow_lines)} 条
# 用途: 功能性白名单例外。请在主拦截规则之前引用:
#   rules:
#     - RULE-SET,adblock-allow,DIRECT
#     - RULE-SET,adblock,REJECT

"""
    allow_path = os.path.join(SCRIPT_DIR, "adblock_allow.txt")
    with open(allow_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(allow_header + "\n".join(allow_lines))
    write_log(f"成功导出 {len(allow_lines)} 条白名单规则至: {allow_path}")

    # 最终汇总输出
    write_log(f"拦截: {final_blocked}, 白名单: {final_whitelisted}, 过滤顶级域: {final_filtered_tld}")
    write_log(f"成功导出 {rule_count} 条规则至: {output_path}")

if __name__ == "__main__":
    main()
