#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Title: AdBlock_Rule_For_Mihomo (Optimized with Intent, PSL & REGEX)
import os
import re
import urllib.request
import datetime
import sys
import yaml
from publicsuffix2 import PublicSuffixList

# 强制标准输出为 UTF-8
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# === 初始化公共后缀列表(PSL) ===
psl = PublicSuffixList()

# === 自定义全局白名单 ===
custom_excluded_domains = [
    # "example.com",
]

# 目录设置
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "adblock_log.txt")
SOURCES_CONFIG = os.path.join(SCRIPT_DIR, "sources.yaml")

# === 预编译正则 + 规则意图枚举 ===
class RegexPatterns:
    # 域名合法性校验
    DOMAIN_VALID = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9.*-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')
    # 规则类型匹配（按优先级排序）
    ADBLOCK_SUFFIX = re.compile(r'^\|\|\*\.([a-zA-Z0-9.*-]+)(?:\^.*)?$')
    ADBLOCK_EXACT = re.compile(r'^\|\|([a-zA-Z0-9.*-]+)(?:\^.*)?$')
    HOSTS_EXACT = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.*-]+)')
    DNSMASQ_SUFFIX = re.compile(r'^(?:address|server)=/([a-zA-Z0-9.*-]+)/')
    CLASH_SUFFIX = re.compile(r'^DOMAIN-SUFFIX\s*,\s*([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})(?:\s*,.*)?$', re.IGNORECASE)
    CLASH_EXACT = re.compile(r'^DOMAIN\s*,\s*([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})(?:\s*,.*)?$', re.IGNORECASE)
    CLASH_WILDCARD = re.compile(r'^DOMAIN-WILDCARD\s*,\s*([a-zA-Z0-9.*-]+)(?:\s*,.*)?$', re.IGNORECASE)
    CLASH_REGEX = re.compile(r'^DOMAIN-REGEX\s*,\s*(.+?)(?:\s*,.*)?$', re.IGNORECASE)
    PURE_DOMAIN = re.compile(r'^([a-zA-Z0-9.*-]+)$')

class RuleIntent:
    EXACT = "exact"
    SUFFIX = "suffix"
    WILDCARD = "wildcard"
    REGEX = "regex"

# === 基础工具函数 ===
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
    default_sources = {
        "allow_urls": [],
        "tier1_urls": [],
        "tier2_urls": [],
        "tier3_urls": []
    }
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

# === 优化1：解析逻辑重构（新增原生 REGEX/WILDCARD 支持） ===
def parse_line_to_rule_info(line: str) -> tuple[str | None, str | None, bool]:
    line = line.strip()
    if not line or line.startswith(("!", "#", "[", ";", "//")):
        return None, None, False
    
    is_whitelist = line.startswith("@@")
    if is_whitelist:
        line = line[2:].strip()
    
    domain = None
    intent = None

    # 优先识别 Clash 原生规则
    if m := RegexPatterns.CLASH_REGEX.match(line):
        return m.group(1), RuleIntent.REGEX, is_whitelist
    if m := RegexPatterns.CLASH_WILDCARD.match(line):
        domain = m.group(1).strip('.')
        intent = RuleIntent.WILDCARD
    elif m := RegexPatterns.CLASH_SUFFIX.match(line):
        domain = m.group(1).strip('.')
        intent = RuleIntent.SUFFIX
    elif m := RegexPatterns.CLASH_EXACT.match(line):
        domain = m.group(1).strip('.')
        intent = RuleIntent.EXACT
    # 识别其他格式规则
    elif m := RegexPatterns.ADBLOCK_SUFFIX.match(line):
        domain = m.group(1).strip('.')
        intent = RuleIntent.SUFFIX
    elif m := RegexPatterns.DNSMASQ_SUFFIX.match(line):
        domain = m.group(1).strip('.')
        intent = RuleIntent.SUFFIX
    elif m := RegexPatterns.ADBLOCK_EXACT.match(line):
        domain = m.group(1).strip('.')
        intent = RuleIntent.SUFFIX if domain.startswith('*.') else RuleIntent.EXACT
    elif m := RegexPatterns.HOSTS_EXACT.match(line):
        domain = m.group(1).strip('.')
        intent = RuleIntent.EXACT
    elif m := RegexPatterns.PURE_DOMAIN.match(line):
        domain = m.group(1).strip('.')
        intent = RuleIntent.EXACT

    # 合法性校验
    if intent == RuleIntent.REGEX:
        return domain, intent, is_whitelist
    if domain and RegexPatterns.DOMAIN_VALID.match(domain):
        domain = domain.lower()
        if '*' in domain and intent != RuleIntent.WILDCARD:
            intent = RuleIntent.WILDCARD
        return domain, intent, is_whitelist
    return None, None, is_whitelist

# === 优化2：PSL 后缀安全校验 ===
def is_valid_suffix_domain(domain: str) -> bool:
    if '*' in domain:
        return False
    registrable_domain = psl.get_sld(domain)
    return registrable_domain == domain

# === 新增：通配符/正则转换逻辑（含 DOMAIN-REGEX 生成） ===
def convert_wildcard_or_regex(content: str, intent: str) -> tuple[str, str]:
    """
    智能转换通配符/正则内容，优先使用高优先级规则类型
    返回 (规则类型, 规则内容)
    """
    # 如果是原生正则，直接保留
    if intent == RuleIntent.REGEX:
        return "DOMAIN-REGEX", content

    # 情况1：标准 *.example.com 格式，优先转 DOMAIN-SUFFIX
    if content.startswith('*.') and '*' not in content[2:]:
        root_domain = content[2:]
        if is_valid_suffix_domain(root_domain):
            return "DOMAIN-SUFFIX", root_domain
        return "DOMAIN-WILDCARD", content

    # 定义正则特殊字符（除了 *，因为 * 是 Mihomo 通配符支持的）
    regex_special_chars = r'^$+{}[]()|\\?:'
    # 情况2：含正则特殊字符，必须转 DOMAIN-REGEX
    if any(char in content for char in regex_special_chars):
        # 安全转义：先转义所有正则特殊字符，再把 * 还原为 .*
        escaped = re.escape(content).replace(r'\*', '.*')
        regex_pattern = f"^{escaped}$"
        return "DOMAIN-REGEX", regex_pattern

    # 情况3：普通通配符（仅含 *），直接用 DOMAIN-WILDCARD
    return "DOMAIN-WILDCARD", content

# === 规则提取函数（适配 REGEX） ===
def extract_rules(urls, exact_set, suffix_set, wildcard_set, regex_set, global_whitelist, force_whitelist=False):
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
            domain, intent, is_whitelist = parse_line_to_rule_info(line)
            if not domain and intent != RuleIntent.REGEX:
                continue
            is_whitelist = force_whitelist or is_whitelist
            if is_whitelist:
                if domain:
                    global_whitelist.add(domain)
                continue
            # 按意图分类存储
            if intent == RuleIntent.EXACT:
                exact_set.add(domain)
            elif intent == RuleIntent.SUFFIX:
                suffix_set.add(domain)
            elif intent == RuleIntent.WILDCARD:
                wildcard_set.add(domain)
            elif intent == RuleIntent.REGEX:
                regex_set.add(domain)

# === 完整规则转换（含 DOMAIN-REGEX） ===
def convert_to_safe_rules(exact_set, suffix_set, wildcard_set, regex_set, whitelist):
    formatted_rules = []
    stats = {
        "DOMAIN": 0,
        "DOMAIN-SUFFIX": 0,
        "DOMAIN-WILDCARD": 0,
        "DOMAIN-REGEX": 0,
        "whitelisted": 0,
        "psl_rejected": 0
    }

    # 1. 处理精确匹配规则
    for domain in exact_set:
        if domain in whitelist:
            stats["whitelisted"] += 1
            continue
        formatted_rules.append(f"- DOMAIN,{domain}")
        stats["DOMAIN"] += 1

    # 2. 处理后缀匹配规则（PSL 校验）
    for domain in suffix_set:
        if domain in whitelist:
            stats["whitelisted"] += 1
            continue
        if not is_valid_suffix_domain(domain):
            write_log(f"PSL校验拒绝：禁止对公共后缀生成后缀拦截 - {domain}（已退化为精确匹配）")
            stats["psl_rejected"] += 1
            formatted_rules.append(f"- DOMAIN,{domain}")
            stats["DOMAIN"] += 1
            continue
        formatted_rules.append(f"- DOMAIN-SUFFIX,{domain}")
        stats["DOMAIN-SUFFIX"] += 1

    # 3. 处理通配符规则（智能转换为 WILDCARD/SUFFIX/REGEX）
    for domain in wildcard_set:
        if domain in whitelist:
            stats["whitelisted"] += 1
            continue
        rule_type, content = convert_wildcard_or_regex(domain, RuleIntent.WILDCARD)
        formatted_rules.append(f"- {rule_type},{content}")
        stats[rule_type] += 1

    # 4. 处理原生正则规则
    for regex_pattern in regex_set:
        formatted_rules.append(f"- DOMAIN-REGEX,{regex_pattern}")
        stats["DOMAIN-REGEX"] += 1

    return formatted_rules, stats

def main():
    write_log("==== 开始初始化设置 (优化版：意图+PSL+REGEX) ====")
    sources = load_sources()
    allow_urls = sources["allow_urls"]
    tier1_urls = sources["tier1_urls"]
    tier2_urls = sources["tier2_urls"]
    tier3_urls = sources["tier3_urls"]

    # 初始化分类集合（新增 regex_set）
    white_set = set(d.lower() for d in custom_excluded_domains)
    exact_set, suffix_set, wildcard_set, regex_set = set(), set(), set(), set()
    tier3_exact, tier3_suffix, tier3_wildcard, tier3_regex = set(), set(), set(), set()

    # 加载本地白名单
    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        for line in safe_read_file(top_whitelist_file):
            domain, _, is_whitelist = parse_line_to_rule_info(line)
            if domain and is_whitelist:
                white_set.add(domain.lower())
        write_log(f"已加载本地白名单，当前白名单库共 {len(white_set)} 条。")

    # 提取规则
    extract_rules(allow_urls, exact_set, suffix_set, wildcard_set, regex_set, white_set, force_whitelist=True)
    extract_rules(tier1_urls + tier2_urls, exact_set, suffix_set, wildcard_set, regex_set, white_set)
    extract_rules(tier3_urls, tier3_exact, tier3_suffix, tier3_wildcard, tier3_regex, white_set)

    # Tier3 冲突清洗
    write_log(">> 正在执行冲突清洗...")
    protected_ancestors = set()
    all_protected = white_set.union(exact_set, suffix_set, wildcard_set)
    for domain in all_protected:
        if '*' in domain:
            continue
        parts = domain.split('.')
        for i in range(len(parts)):
            protected_ancestors.add('.'.join(parts[i:]))
    
    valid_tier3_exact = {d for d in tier3_exact if d not in protected_ancestors}
    valid_tier3_suffix = {d for d in tier3_suffix if d not in protected_ancestors}
    valid_tier3_wildcard = tier3_wildcard
    valid_tier3_regex = tier3_regex

    # 合并最终规则集
    final_exact = exact_set.union(valid_tier3_exact)
    final_suffix = suffix_set.union(valid_tier3_suffix)
    final_wildcard = wildcard_set.union(valid_tier3_wildcard)
    final_regex = regex_set.union(valid_tier3_regex)

    # 执行安全转换
    write_log(">> 正在执行安全规则转换...")
    formatted_rules, stats = convert_to_safe_rules(final_exact, final_suffix, final_wildcard, final_regex, white_set)

    # 生成输出
    rule_count = len(formatted_rules)
    generation_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    header = f"""# Title: AdBlock_Rule_For_Mihomo (Safe Optimized)
# Generated: {generation_time} (UTC+8)
# Total Items: {rule_count} 条
# -----------------------------------------------
# 统计信息:
# - [DOMAIN]          : {stats['DOMAIN']} 条
# - [DOMAIN-SUFFIX]   : {stats['DOMAIN-SUFFIX']} 条
# - [DOMAIN-WILDCARD] : {stats['DOMAIN-WILDCARD']} 条
# - [DOMAIN-REGEX]    : {stats['DOMAIN-REGEX']} 条
# -----------------------------------------------
# 安全过滤信息:
# - 白名单过滤: {stats['whitelisted']} 条
# - PSL校验拒绝: {stats['psl_rejected']} 条 (已退化为精确匹配)
# -----------------------------------------------
payload:
"""
    output_path = os.path.join(SCRIPT_DIR, "adblock_reject_safe.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(formatted_rules))
    write_log(f"成功导出 {rule_count} 条安全规则至: {output_path}")
    write_log(f"规则统计：DOMAIN {stats['DOMAIN']}, SUFFIX {stats['DOMAIN-SUFFIX']}, WILDCARD {stats['DOMAIN-WILDCARD']}, REGEX {stats['DOMAIN-REGEX']}")

if __name__ == "__main__":
    main()
