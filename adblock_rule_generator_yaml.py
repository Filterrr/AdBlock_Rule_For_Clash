import urllib.request
import re
import os

# ==================== 配置区 ====================
# 这里填入你需要转换的 Adblock 规则订阅链接
ADBLOCK_URLS =[
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt",
    # 在这里添加更多链接...
]

# 全局白名单（在此列表中的域名和关键字不会被拦截）
WHITELIST = {
    "apple.com", 
    "microsoft.com", 
    "github.com"
}

# 输出的文件名
OUTPUT_YAML = "mihomo_adblock_rules.yaml"

# 标准域名正则表达式 (用于区分提取出的是域名还是关键字)
# 匹配诸如: example.com, ads.google.com
DOMAIN_REGEX = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

# ================================================

def fetch_and_parse():
    domain_suffix_set = set()
    domain_keyword_set = set()
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    for url in ADBLOCK_URLS:
        print(f"[*] 正在获取并解析: {url}")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as response:
                content = response.read().decode('utf-8')
                
                for line in content.splitlines():
                    line = line.strip()
                    
                    # 1. 忽略空行和注释
                    if not line or line.startswith(('!', '#', '[')):
                        continue
                    
                    # 2. 去除 Adblock 规则的修饰符选项 (例如 $third-party,script)
                    line = line.split('$')[0].strip()
                    
                    # 3. 【核心修改】直接丢弃包含 '/' 的规则 (Mihomo 无法匹配路径)
                    # 例如: -1688-wp-media/ads/ 或 .bid/ads/ 会被直接丢弃
                    if '/' in line:
                        continue
                    
                    # 4. 去除包含 '*' 的泛解析规则 (为了性能，不在 Mihomo 使用复杂的正则匹配)
                    if '*' in line:
                        continue

                    # 5. 去除 Adblock 特有的前缀 (||) 和后缀 (^)
                    rule = line.lstrip('|').rstrip('^').strip()
                    
                    # 6. 如果提取后为空，跳过
                    if not rule:
                        continue
                    
                    # 7. 白名单检查
                    if rule in WHITELIST:
                        continue

                    # 8. 【核心分类逻辑】区分 DOMAIN-SUFFIX 和 DOMAIN-KEYWORD
                    if DOMAIN_REGEX.match(rule):
                        # 如果匹配标准的域名格式 -> 归类为 SUFFIX
                        domain_suffix_set.add(rule)
                    else:
                        # 如果不匹配标准域名 (例如以 '-' 开头、包含不规则符号) -> 归类为 KEYWORD
                        # 示例: -1367066484.cos. 会进入这里
                        
                        # 安全防误杀：忽略长度太短的关键字
                        if len(rule) >= 4:
                            domain_keyword_set.add(rule)
                        else:
                            pass # 忽略类似 "ad." 这种极易误杀的超短关键字
                            
        except Exception as e:
            print(f"[!] 获取 {url} 失败: {e}")

    return domain_suffix_set, domain_keyword_set

def generate_yaml(suffixes, keywords, output_file):
    print(f"[*] 解析完成！共提取:")
    print(f"    - DOMAIN-SUFFIX: {len(suffixes)} 条")
    print(f"    - DOMAIN-KEYWORD: {len(keywords)} 条")
    
    print(f"[*] 正在生成 {output_file} ...")
    
    # 将集合按字母排序，使输出的文件更加整洁
    sorted_suffixes = sorted(list(suffixes))
    sorted_keywords = sorted(list(keywords))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Generated Adblock Rules for Mihomo/Clash\n")
        f.write("payload:\n")
        
        # 写入后缀规则
        for suffix in sorted_suffixes:
            f.write(f"  - DOMAIN-SUFFIX,{suffix}\n")
            
        # 写入关键字规则
        for keyword in sorted_keywords:
            f.write(f"  - DOMAIN-KEYWORD,{keyword}\n")

    print("[*] 成功生成文件！")

if __name__ == "__main__":
    # 执行流程
    suffixes, keywords = fetch_and_parse()
    generate_yaml(suffixes, keywords, OUTPUT_YAML)
