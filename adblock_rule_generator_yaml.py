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
custom_excluded_domains =[
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

# 新增关键字正则匹配：允许提取如 .bid/ads/、-1316632262.cos. 这种包含 /、_ 以及 - 和 . 等字符的规则
regex_keyword = re.compile(r'^([-.a-zA-Z0-9/_*]+)$')

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
        # publicsuffixlist 的 privatesuffix 返回注册域部分
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
    encodings =['utf-8-sig', 'utf-8', 'gbk', 'latin-1']
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                return f.readlines()
        except Exception:
            continue
    return[]

# --- 加载外部订阅源配置 ---
def load_sources(config_path=SOURCES_CONFIG):
    default_sources = {
        "allow_urls": [],
        "tier1_urls":[],
        "tier2_urls": [],
        "tier3_urls":[]
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

# --- 通用域名/关键字提取器 ---
def parse_line(line):
    """统一提取域名或关键字，返回元组 (类型, 值)"""
    if line.startswith("@@"):
        line = line[2:]

    val = None
    if m := regex1.match(line): val = m.group(1)
    elif m := regex2.match(line): val = m.group(1)
    elif m := regex3.match(line): val = m.group(1)
    elif m := regex4.match(line): val = m.group(1)
    elif m := regex_keyword.match(line): val = m.group(1)

    if val:
        val_stripped = val.strip('.')
        # 如果符合标准域名规范，则返回 DOMAIN
        if domain_regex.match(val_stripped):
            return ('DOMAIN', val_stripped.lower())
        # 否则判定为关键字，返回 KEYWORD (这里保留用户规则原始的末尾点或斜杠)
        else:
            return ('KEYWORD', val.lower())
            
    return (None, None)

def extract_rules(urls, rules_set, keyword_set, global_whitelist, keyword_whitelist, force_whitelist=False):
    """
    提取规则
    :param force_whitelist: 如果为 True，无论规则有无 @@ 前缀，均强制视为白名单
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

            # 使用分类解析器提取
            parsed_type, val = parse_line(line)

            if parsed_type == 'DOMAIN':
                domain = val
                # 过滤公共后缀（如 "com", "co.uk"）
                if is_public_suffix(domain):
                    skipped_psl += 1
                    continue
                if is_whitelist:
                    global_whitelist.add(domain)
                else:
                    rules_set.add(domain)
            elif parsed_type == 'KEYWORD':
                keyword = val
                if is_whitelist:
                    keyword_whitelist.add(keyword)
                else:
                    keyword_set.add(keyword)
                    
    if skipped_psl:
        write_log(f"已过滤 {skipped_psl} 条公共后缀域名规则")

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

    # 从外部配置文件加载订阅源
    sources = load_sources()
    allow_urls = sources["allow_urls"]
    tier1_urls = sources["tier1_urls"]
    tier2_urls = sources["tier2_urls"]
    tier3_urls = sources["tier3_urls"]

    white_set = set(d.lower() for d in custom_excluded_domains)
    keyword_white_set = set()
    core_set_raw, tier3_set_raw = set(), set()
    keyword_set_raw, keyword_tier3_set_raw = set(), set()

    # 优化：加载本地高权重白名单 (支持纯域名及各种复杂规则格式)
    top_whitelist_file = os.path.join(SCRIPT_DIR, "top_whitelist.txt")
    if os.path.exists(top_whitelist_file):
        for line in safe_read_file(top_whitelist_file):
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                continue

            parsed_type, val = parse_line(line)
            if parsed_type == 'DOMAIN':
                domain = val
                if not is_public_suffix(domain):
                    white_set.add(domain)
            elif parsed_type == 'KEYWORD':
                keyword_white_set.add(val)
        write_log(f"已加载本地白名单，当前白名单库共 {len(white_set)} 条，关键字白名单 {len(keyword_white_set)} 条。")

    # 获取规则 (优化：allow_urls 开启强制白名单模式)
    extract_rules(allow_urls, core_set_raw, keyword_set_raw, white_set, keyword_white_set, force_whitelist=True)
    extract_rules(tier1_urls + tier2_urls, core_set_raw, keyword_set_raw, white_set, keyword_white_set)
    extract_rules(tier3_urls, tier3_set_raw, keyword_tier3_set_raw, white_set, keyword_white_set)

    # 阶段 1 & 2：预处理与冲突检测
    write_log(">> 正在执行冲突清洗与保护机制校验...")
    valid_core = {d for d in core_set_raw if d not in white_set}
    valid_keyword_core = {k for k in keyword_set_raw if k not in keyword_white_set}

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
        
    valid_keyword_tier3 = {k for k in keyword_tier3_set_raw if k not in keyword_white_set}

    # 阶段 4：Mihomo 格式智能转换
    write_log(">> 正在执行 Mihomo 匹配类型自动分类...")
    all_domains = valid_core.union(valid_tier3)
    all_keywords = valid_keyword_core.union(valid_keyword_tier3)

    suffix_candidates = {d for d in all_domains if '*' not in d}
    global_subs_detector = set()
    for d in suffix_candidates:
        temp = d
        while '.' in temp:
            temp = temp[temp.find('.')+1:]
            global_subs_detector.add(temp)

    optimized_domains = [d for d in all_domains if d not in global_subs_detector]
    # 为关键字增加基础的安全检查：过滤因拼写错误等导致过于宽泛的极短关键字规则 (至少2位字符)
    optimized_keywords =[k for k in all_keywords if len(k) >= 2]

    # --- 计数器 ---
    count_wildcard = 0
    count_regex = 0
    count_exact = 0
    count_suffix = 0
    count_keyword = 0

    formatted_rules =[]
    
    # 域名处理部分
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

        if domain.count('.') >= 3:
            registrable = get_registrable_domain(domain)
            if registrable and domain == registrable:
                formatted_rules.append(f"- DOMAIN-SUFFIX,{domain}")
                count_suffix += 1
            else:
                formatted_rules.append(f"- DOMAIN,{domain}")
                count_exact += 1
            continue

        formatted_rules.append(f"- DOMAIN-SUFFIX,{domain}")
        count_suffix += 1

    # 关键字处理部分：输出为 DOMAIN-KEYWORD
    for keyword in sorted(optimized_keywords):
        formatted_rules.append(f"- DOMAIN-KEYWORD,{keyword}")
        count_keyword += 1

    def rule_sort_key(rule):
        # 提取规则前缀用于判断优先级
        if rule.startswith("- DOMAIN,"): return 1
        if rule.startswith("- DOMAIN-SUFFIX,"): return 2
        if rule.startswith("- DOMAIN-WILDCARD,"): return 3
        if rule.startswith("- DOMAIN-KEYWORD,"): return 4
        if rule.startswith("- DOMAIN-REGEX,"): return 5
        return 99

    # 按照 规则类型优先级排列，同类型下再按字母表顺序进行二次排列
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
# -[DOMAIN-KEYWORD] : {count_keyword} 条
# - [DOMAIN-REGEX]   : {count_regex} 条
# -----------------------------------------------

payload:
"""
    output_path = os.path.join(SCRIPT_DIR, "adblock_reject.yaml")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(formatted_rules))

    write_log(f"成功导出 {rule_count} 条规则至: {output_path}")

if __name__ == "__main__":
    main()
