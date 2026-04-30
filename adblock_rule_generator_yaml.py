#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Title: AdBlock_Rule_For_Mihomo
# Description: 专为 Mihomo 内核优化的广告拦截规则生成脚本
#              支持 DOMAIN-KEYWORD 兜底匹配畸形域名片段


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
    """
    从外部 YAML 文件读取订阅源 URL 列表。
    返回字典，包含 'allow_urls', 'tier1_urls', 'tier2_urls', 'tier3_urls' 键。
    若文件不存在或格式错误，则返回空列表的字典。
    """
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

    # 确保每个键都存在且为列表
    for key in default_sources:
        if key not in sources or not isinstance(sources[key], list):
            sources[key] = default_sources[key]
    return sources

# --- 通用域名提取器 ---
def parse_line_to_domain(line):
    """统一使用正则提取域名，兼容各种规则格式"""
    if line.startswith("@@"):
        line = line[2:]

    domain = None
    if m := regex1.match(line): domain = m.group(1)
    elif m := regex2.match(line): domain = m.group(1)
    elif m := regex3.match(line): domain = m.group(1)
    elif m := regex4.match(line): domain = m.group(1)
    elif m := regex5.match(line): domain = m.group(1)

    return domain.strip('.') if domain else None

def extract_keyword_for_domain_rule(line):
    """
    尝试从一行规则中提取可用于 DOMAIN-KEYWORD 的关键字。
    仅处理：不含路径，且看起来像域名片段（包含点）的条目。
    返回：关键字字符串（已去除首尾特殊字符，长度>=5），或 None
    """
    # 移除开头的 @@ 或 ||
    cleaned = re.sub(r'^(?:@@|\|\|)', '', line).strip()
    # 去掉通配符、首尾的 . 和 - 以及 ^ 等
    cleaned = cleaned.strip('.*-^ ')
    # 如果包含路径（/）则不处理（这不是域名片段）
    if '/' in cleaned:
        return None
    # 必须包含点，且剩余字符为可能的域名片段
    if '.' not in cleaned:
        return None
    # 进一步清理：移除可能残留的前缀如 "address=/" 等
    if '=' in cleaned:
        return None
    # 只保留 [a-zA-Z0-9.-] 字符
    keyword = re.sub(r'[^a-zA-Z0-9.-]', '', cleaned)
    # 去掉首尾的点或连字符，得到核心关键字
    keyword = keyword.strip('.-')
    # 长度至少 5 个字符，避免过短关键字（如 "co.in" 不足5也会跳过）
    if len(keyword) >= 5:
        return keyword.lower()
    return None

def extract_rules(urls, rules_set, global_whitelist, force_whitelist=False, keyword_set=None):
    """
    提取规则
    :param force_whitelist: 如果为 True，无论规则有无 @@ 前缀，均强制视为白名单
    :param keyword_set: 若提供，会将无法识别为标准域名的条目提取为关键字集
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    skipped_psl = 0
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

            # 判断是否为白名单（强制模式 or 自带 @@ 前缀）
            is_whitelist = force_whitelist or line.startswith("@@")

            # 使用通用解析器提取域名
            domain = parse_line_to_domain(line)

            if domain and domain_regex.match(domain):
                domain = domain.lower()
                # 过滤公共后缀（如 "com", "co.uk"）
                if is_public_suffix(domain):
                    skipped_psl += 1
                    continue
                if is_whitelist:
                    global_whitelist.add(domain)
                else:
                    rules_set.add(domain)
            else:
                # 域名格式不符合标准，尝试提取为 DOMAIN-KEYWORD（仅针对黑名单规则）
                if not is_whitelist and keyword_set is not None:
                    kw = extract_keyword_for_domain_rule(line)
                    if kw:
                        keyword_set.add(kw)
    if skipped_psl:
        write_log(f"已过滤 {skipped_psl} 条公共后缀域名规则")

def wildcard_to_regex(domain):
    """
    将 Adblock 通配符域名转换为 Mihomo 可用的正则表达式
    只处理含有 * 的域名，转换规则：
    - 转义正则特殊字符（. ? + 等）
    - 将 * 替换为 .*
    - 添加行首行尾锚定
    若 * 只出现在开头且紧跟着 '.', 返回 None 表示应使用 DOMAIN-WILDCARD
    """
    if '*' not in domain:
        return None
    # 如果符合 *.example.com 这种简单格式，交给 DOMAIN-WILDCARD
    if domain.startswith('*.') and '*' not in domain[2:]:
        return None
    # 复杂通配符：转义除 * 外的正则符号，然后把 * 换成 .*
    escaped = re.escape(domain)
    regex_str = escaped.replace(r'\*', '.*')
    return f"^{regex_str}$"

def main():
    write_log("==== 开始初始化设置 ====")

    # 从外部配置文件加载订阅源
    sources = load_sources()
    allow_urls = sources["allow_urls"]
    tier1_urls = sources["tier1_urls"]
    tier2_urls = sources["tier2_urls"]
    tier3_urls = sources["tier3_urls"]

    white_set = set(d.lower() for d in custom_excluded_domains)
    core_set_raw, tier3_set_raw = set(), set()
    keyword_set = set()  # 收集无法识别为域名的关键字

    # 优化：加载本地高权重白名单 (支持纯域名及各种复杂规则格式)
    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        for line in safe_read_file(top_whitelist_file):
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                continue

            domain = parse_line_to_domain(line)
            if domain and domain_regex.match(domain):
                domain = domain.lower()
                if not is_public_suffix(domain):
                    white_set.add(domain)
        write_log(f"已加载本地白名单，当前白名单库共 {len(white_set)} 条。")

    # 获取规则 (优化：allow_urls 开启强制白名单模式)
    extract_rules(allow_urls, core_set_raw, white_set, force_whitelist=True)
    extract_rules(tier1_urls + tier2_urls, core_set_raw, white_set, keyword_set=keyword_set)
    extract_rules(tier3_urls, tier3_set_raw, white_set, keyword_set=keyword_set)

    # 阶段 1 & 2：预处理与冲突检测
    write_log(">> 正在执行冲突清洗与保护机制校验...")
    valid_core = {d for d in core_set_raw if d not in white_set}

    # 构建父级保护伞（防止 Tier 3 误杀白名单或核心列表中的域名的父级）
    protected_ancestors = set()
    for s in (white_set, valid_core):
        for item in s:
            if '*' in item: continue
            curr = item
            protected_ancestors.add(curr)
            while '.' in curr:
                curr = curr[curr.find('.')+1:]
                protected_ancestors.add(curr)

    # 阶段 3：过滤 Tier 3
    valid_tier3 = set()
    for d in tier3_set_raw:
        if d in protected_ancestors or '*' in d:
            if '*' in d: valid_tier3.add(d)   # 通配符直接放行
            continue
        valid_tier3.add(d)

    # 阶段 4：Mihomo 格式智能转换
    write_log(">> 正在执行 Mihomo 域名匹配类型自动分类...")
    all_domains = valid_core.union(valid_tier3)

    suffix_candidates = {d for d in all_domains if '*' not in d}
    global_subs_detector = set()
    for d in suffix_candidates:
        temp = d
        while '.' in temp:
            temp = temp[temp.find('.')+1:]
            global_subs_detector.add(temp)

    optimized_domains = [d for d in all_domains if d not in global_subs_detector]

    # --- 计数器 ---
    count_wildcard = 0
    count_regex = 0
    count_exact = 0
    count_suffix = 0
    count_keyword = 0

    formatted_rules = []
    # 处理标准域名规则
    for domain in sorted(optimized_domains):
        # 情况 1: 含通配符 -> DOMAIN-WILDCARD 或 DOMAIN-REGEX
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

        # 情况 2: 普通域名（无通配符）分类
        if domain.count('.') >= 3:
            registrable = get_registrable_domain(domain)
            if registrable and domain == registrable:
                # 该域名本身是注册域（例如 example.com.cn），应后缀匹配
                formatted_rules.append(f"- DOMAIN-SUFFIX,{domain}")
                count_suffix += 1
            else:
                # 深层子域，保持精确匹配
                formatted_rules.append(f"- DOMAIN,{domain}")
                count_exact += 1
            continue

        # 情况 3: 常规二/三级域名 -> DOMAIN-SUFFIX
        formatted_rules.append(f"- DOMAIN-SUFFIX,{domain}")
        count_suffix += 1

    # 追加 DOMAIN-KEYWORD 规则（来自畸形片段）
    for kw in sorted(keyword_set):
        formatted_rules.append(f"- DOMAIN-KEYWORD,{kw}")
        count_keyword += 1

    def rule_sort_key(rule):
        # 提取规则前缀用于判断优先级
        if rule.startswith("- DOMAIN,"): return 1
        if rule.startswith("- DOMAIN-SUFFIX,"): return 2
        if rule.startswith("- DOMAIN-WILDCARD,"): return 3
        if rule.startswith("- DOMAIN-REGEX,"): return 4
        if rule.startswith("- DOMAIN-KEYWORD,"): return 5
        return 99

    # 按照规则类型优先级排列，同类型下再按字母表顺序进行二次排列
    formatted_rules.sort(key=lambda x: (rule_sort_key(x), x))

    # 输出文件
    rule_count = len(formatted_rules)
    generation_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    header = f"""# Title: AdBlock_Rule_For_Mihomo
# Generated: {generation_time} (UTC+8)
# Total Items: {rule_count} 条
# -----------------------------------------------
# 统计信息:
# - [DOMAIN]         : {count_exact} 条
# - [DOMAIN-SUFFIX]  : {count_suffix} 条
# - [DOMAIN-WILDCARD]: {count_wildcard} 条
# - [DOMAIN-REGEX]   : {count_regex} 条
# - [DOMAIN-KEYWORD] : {count_keyword} 条
# -----------------------------------------------

payload:
"""
    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(formatted_rules))

    write_log(f"成功导出 {rule_count} 条规则至: {output_path}")

if __name__ == "__main__":
    main()
