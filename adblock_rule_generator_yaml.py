#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Title: AdBlock_Rule_For_Mihomo
# Description: 专为 Mihomo 内核优化的广告拦截规则生成脚本

import os
import re
import urllib.request
import datetime
import sys
import yaml  # 需要安装 PyYAML: pip install pyyaml

# 强制标准输出为 UTF-8
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# --- 尝试导入 publicsuffixlist (需安装: pip install publicsuffixlist) ---
try:
    from publicsuffixlist import PublicSuffixList
except ImportError:
    PublicSuffixList = None
    print("⚠️ 警告: 未安装 publicsuffixlist，将退回到简单的点数判断。")
    print("    (建议执行: pip install publicsuffixlist)")

# === 自定义全局白名单 ===
custom_excluded_domains = [
    # "example.com",
]

# 目录设置
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, "adblock_log.txt")
SOURCES_CONFIG = os.path.join(SCRIPT_DIR, "sources.yaml")

# --- 增强型正则引擎：支持通配符 (*) 提取 ---
domain_regex = re.compile(r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9.*-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$')
regex1 = re.compile(r'^\|\|([a-zA-Z0-9.*-]+)(?:\^.*)?$')
regex2 = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.*-]+)')
regex3 = re.compile(r'^(?:address|server)=/([a-zA-Z0-9.*-]+)/')
regex4 = re.compile(r'^(?:DOMAIN|HOST)(?:-SUFFIX|0WILD)?\s*,\s*([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})(?:\s*,.*)?$', re.IGNORECASE)
regex5 = re.compile(r'^([a-zA-Z0-9.*-]+)$')

# --- 初始化 PublicSuffixList ---
_psl = PublicSuffixList() if PublicSuffixList else None

def is_public_suffix(domain):
    """检查域名是否为公共后缀 (如 'com', 'co.uk')，若是则返回 True"""
    if _psl is None:
        return False
    try:
        return _psl.is_public_suffix(domain)
    except Exception:
        return False

def get_registrable_domain(domain):
    """获取域名的注册域 (eTLD+1)，例如 'example.com.cn'。失败返回 None"""
    if _psl is None:
        return None
    try:
        return _psl.privatesuffix(domain)
    except Exception:
        return None

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

# --- 加载外部订阅源配置 ---
def load_sources(config_path=SOURCES_CONFIG):
    default_sources = {
        "allow_urls": [],
        "tier1_urls": [],
        "tier2_urls": [],
        "tier3_urls": [],
        "tier4_urls": []
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

# --- 通用域名提取器 ---
def parse_line_to_domain(line: str) -> str | None:
    # 去除白名单前缀
    if line.startswith("@@"):
        line = line[2:]

    domain = None
    if m := regex1.match(line):
        domain = m.group(1)
    elif m := regex2.match(line):
        domain = m.group(1)
    elif m := regex3.match(line):
        domain = m.group(1)
    elif m := regex4.match(line):
        domain = m.group(1)
    elif m := regex5.match(line):
        domain = m.group(1)

    if not domain:
        return None

    # ---------- 集中规范化 ----------
    # 去除首尾的点
    domain = domain.strip('.')
    # 转为小写
    domain = domain.lower()
    # 可选：如果存在空格或不可见字符，也可以在此清洗
    domain = domain.strip()
    # ---------------------------------

    # 空字符串检查
    return domain if domain else None
    # ---------------------------------

def is_global_exception(line: str) -> bool:
    """
    判断 @@ 行是否为『真·全局白名单』。

    上游过滤器的 @@ 例外分为两类：
      1. 全局豁免（无任何修饰符），例如：@@||example.org^
      2. 站点/资源级豁免，例如：
         - @@||doubleclick.net^$xmlhttprequest,domain=yyets.click  (仅对特定站点放行)
         - @@||qq.com^*?ADTAG=                                     (仅豁免特定 URL 参数)
         - @@||verb.tw^$generichide                                (仅隐藏元素)
    只有第 1 类才应进入全局白名单；第 2 类若被当成全局白名单，
    会导致对应域名（如 doubleclick.net、googlesyndication.com）被整体放行。
    """
    if '$' in line:
        return False  # 任何带修饰符的豁免都不是全局豁免
    core = line[2:] if line.startswith('@@') else line
    if re.match(r'^\|\|([a-zA-Z0-9.*-]+)\^(.+)$', core):
        return False  # ||dom^ANYTHING（URL 级豁免）
    if core.startswith('||'):
        rest = core[2:]
        if '/' in rest:
            return False  # ||dom/path
        return True
    if '/' in core:
        return False  # @@/path 或 @@sub/path
    return True

# --- 可安全收编的资源修饰符（无 domain= 时语义等价于该域全局拦截） ---
ADOPTABLE_MODIFIERS = {'third-party', 'all', 'document', 'important'}

def parse_block_rule(line: str) -> str | None:
    """
    解析『拦截规则』，只返回【无条件全局域名拦截】意图的域名。

    上游规则中存在仅对特定站点/资源生效的条件性规则（如带 $domain= 的站点级限制、
    带 $popup 的资源类型限制）。这些规则的域名不应被当作无条件拦截目标，
    否则会误杀整个域（例如 ||taobao.com^$popup,domain=52movieba.com 若直接提取
    会封禁整个淘宝）。
    本函数只接受以下明确形态：
      - ||domain^           纯域名锚定
      - ||domain            纯域名锚定（无结尾符）
      - ||domain^$third-party / $all / $document / $important（无站点限制的全局拦截）
      - 0.0.0.0/127.0.0.1 domain  (hosts 格式)
      - address=/domain/    (dnsmasq 格式)
      - DOMAIN,domain / DOMAIN-SUFFIX,domain (classical 格式)
      - domain 纯域名行（含 *.domain 通配行）
    其余任何带站点限制/路径/资源类型限制的形态一律返回 None（不提取）。
    """
    # || 形态
    m = re.match(r'^\|\|([a-zA-Z0-9.*-]+)(.*)$', line)
    if m:
        dom, rest = m.group(1), m.group(2)
        if rest == '' or rest == '^':
            if dom.startswith('*.'):
                dom = dom[2:]
            return dom.strip('.').lower() or None
        if rest.startswith('^$'):
            mods_str = rest[2:]
            mods = [s.strip() for s in mods_str.split(',')]
            # 所有修饰符都必须是可安全收编的全局拦截修饰符
            if mods and all(m in ADOPTABLE_MODIFIERS for m in mods):
                if dom.startswith('*.'):
                    dom = dom[2:]
                return dom.strip('.').lower() or None
            return None
        return None

    # hosts 格式
    m = regex2.match(line)
    if m:
        return m.group(1).strip('.').lower() or None

    # dnsmasq 格式
    m = regex3.match(line)
    if m:
        return m.group(1).strip('.').lower() or None

    # classical 格式
    m = regex4.match(line)
    if m:
        return m.group(1).strip('.').lower() or None

    # 纯域名行（支持 *.domain 通配形式；列表格式中 *.domain 与『该域及子域』等价，
    # 统一归一为后缀域名参与去重）
    token = line
    if token.startswith('*.'):
        token = token[2:]
    if re.match(r'^[a-zA-Z0-9.*-]+$', token) and '$' not in token and '.' in token:
        return token.strip('.').lower() or None

    return None

def extract_rules(urls, rules_set, global_whitelist, force_whitelist=False):
    """
    提取规则，返回 (total_block, total_allow, total_psl) 作为该批次的总计数
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    total_block = 0
    total_allow = 0
    total_psl = 0

    write_log(f"开始并获取 {len(urls)} 个订阅源...")

    for url in urls:
        req = urllib.request.Request(url, headers=headers)
        block_cnt = 0
        allow_cnt = 0
        psl_cnt = 0

        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                content = smart_decode(response.read())
        except Exception as e:
            write_log(f"✖ 获取失败: {url} - {e}")
            continue

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                continue

            # ★ 白名单行：仅收『真·全局豁免』（其余站点/资源级豁免不作为全局白名单）
            if line.startswith('@@'):
                if is_global_exception(line):
                    domain = parse_line_to_domain(line)
                    if domain and domain_regex.match(domain):
                        domain = domain.lower()
                        if is_public_suffix(domain):
                            psl_cnt += 1
                            continue
                        global_whitelist.add(domain)
                        allow_cnt += 1
                continue

            if force_whitelist:
                # allow 源整体视为白名单（纯域名列表等）
                domain = parse_line_to_domain(line)
                if domain and domain_regex.match(domain):
                    domain = domain.lower()
                    if is_public_suffix(domain):
                        psl_cnt += 1
                        continue
                    global_whitelist.add(domain)
                    allow_cnt += 1
                continue

            # ★ 拦截行：仅收『无条件全局域名拦截』
            domain = parse_block_rule(line)
            if domain and domain_regex.match(domain):
                domain = domain.lower()
                if is_public_suffix(domain):
                    psl_cnt += 1
                    continue
                rules_set.add(domain)
                block_cnt += 1

        total_block += block_cnt
        total_allow += allow_cnt
        total_psl += psl_cnt
        write_log(f"✔ 解析: {url} (拦截: {block_cnt}, 白名单: {allow_cnt}, 过滤顶级域: {psl_cnt})")

    return total_block, total_allow, total_psl

def wildcard_to_regex(domain):
    if '*' not in domain:
        return None
    if domain.startswith('*.') and '*' not in domain[2:]:
        return None
    escaped = re.escape(domain)
    regex_str = escaped.replace(r'\*', '.*')
    return f"^{regex_str}$"

def main():
    write_log("==== 开始初始化设置 ====")

    sources = load_sources()
    allow_urls = sources["allow_urls"]
    tier1_urls = sources["tier1_urls"]
    tier2_urls = sources["tier2_urls"]
    tier3_urls = sources["tier3_urls"]
    tier4_urls = sources["tier4_urls"]

    white_set = set(d.lower() for d in custom_excluded_domains)
    core_set_raw, tier3_set_raw = set(), set()

    # 加载本地高权重白名单
    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        for line in safe_read_file(top_whitelist_file):
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                continue
            domain = parse_line_to_domain(line)
            if domain and domain_regex.match(domain):
             #   domain = domain.lower()
                if not is_public_suffix(domain):
                    white_set.add(domain)
        write_log(f"已加载本地白名单，当前白名单库共 {len(white_set)} 条。")

    # 获取规则并累计总数（tier4 为高质量 DNS 拦截列表，与 tier3 同池处理）
    block1, allow1, psl1 = extract_rules(allow_urls, core_set_raw, white_set, force_whitelist=True)
    block2, allow2, psl2 = extract_rules(tier1_urls + tier2_urls, core_set_raw, white_set)
    block3, allow3, psl3 = extract_rules(tier3_urls + tier4_urls, tier3_set_raw, white_set)

    total_block = block1 + block2 + block3
    total_allow = allow1 + allow2 + allow3
    total_psl = psl1 + psl2 + psl3

    # 冲突清洗与保护机制
    write_log(">> 正在执行冲突清洗与保护机制校验...")

    # 白名单保护：剔除『属于白名单域名（含子域）』的拦截条目。
    # 说明：只做精确剔除（白名单本体及其子域），不做『祖先保护』——
    # 后者会因个别白名单例外（如 pagead.l.doubleclick.net）而误删整个广告根域
    # （如 doubleclick.net），得不偿失。
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

    # Mihomo 格式转换
    write_log(">> 正在执行 Mihomo 域名匹配类型自动分类...")
    all_domains = valid_core.union(valid_tier3)

    # ★ 修复去重方向：父域存在时删除其子域。
    # DOMAIN-SUFFIX 语义下，父域规则已覆盖全部子域；原实现反向删除了父域，
    # 导致 doubleclick.net 等著名广告大域只剩零星子域，拦截率大幅下降。
    suffix_candidates = {d for d in all_domains if '*' not in d}

    def has_ancestor_in(domain, domain_pool):
        parts = domain.split('.')
        for i in range(1, len(parts)):
            if '.'.join(parts[i:]) in domain_pool:
                return True
        return False

    optimized_domains = {d for d in suffix_candidates if not has_ancestor_in(d, suffix_candidates)}

    # 其余含部分标签通配（ads*.x.com 等）的条目 —— trie 语义不支持，
    # 保留为 DOMAIN-REGEX（仅 classical 格式可用）。
    wildcard_partial = {d for d in all_domains if '*' in d}

    count_wildcard = 0
    count_regex = 0
    count_suffix = 0

    formatted_rules = []
    for domain in sorted(optimized_domains):
        formatted_rules.append(f"- DOMAIN-SUFFIX,{domain}")
        count_suffix += 1

    for domain in sorted(wildcard_partial):
        regex_pattern = wildcard_to_regex(domain)
        if regex_pattern:
            formatted_rules.append(f"- DOMAIN-REGEX,{regex_pattern}")
            count_regex += 1

    def rule_sort_key(rule):
        if rule.startswith("- DOMAIN-SUFFIX,"): return 2
        if rule.startswith("- DOMAIN-WILDCARD,"): return 3
        if rule.startswith("- DOMAIN-REGEX,"): return 4
        return 99

    formatted_rules.sort(key=lambda x: (rule_sort_key(x), x))

    rule_count = len(formatted_rules)
    generation_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    header = f"""# Title: AdBlock_Rule_For_Mihomo
# Generated: {generation_time} (UTC+8)
# Total Items: {rule_count} 条
# -----------------------------------------------
# 规则分类统计:
# - [DOMAIN-SUFFIX]  : {count_suffix} 条
# - [DOMAIN-WILDCARD]: {count_wildcard} 条
# - [DOMAIN-REGEX]   : {count_regex} 条
# -----------------------------------------------

payload:
"""
    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(formatted_rules))

    write_log(f"成功导出 {rule_count} 条规则至: {output_path} (拦截: {total_block}, 白名单: {total_allow}, 过滤顶级域: {total_psl})")

if __name__ == "__main__":
    main()
