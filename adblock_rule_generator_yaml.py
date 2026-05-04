#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Title: AdBlock_Rule_For_Mihomo
# Description: 专为 Mihomo 内核优化的广告拦截规则生成脚本（增强版）

import os
import re
import json
import time
import threading
import datetime
import sys
import urllib.request
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from contextlib import contextmanager
from collections import defaultdict, Counter
from functools import wraps
import concurrent.futures

# 尝试导入 PyYAML
try:
    import yaml
except ImportError:
    print("错误: 需要安装 PyYAML: pip install pyyaml")
    sys.exit(1)

# 强制标准输出为 UTF-8
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# 尝试导入 publicsuffixlist
try:
    from publicsuffixlist import PublicSuffixList
    PSL_AVAILABLE = True
except ImportError:
    PSL_AVAILABLE = False
    PublicSuffixList = None
    print("⚠️ 警告: 未安装 publicsuffixlist，将退回到简单的点数判断。")
    print("    (建议执行: pip install publicsuffixlist)")

# ============================================================================
# 配置常量
# ============================================================================
@dataclass
class Config:
    """全局配置"""
    # 文件路径
    SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))
    LOG_FILE: str = field(default_factory=lambda: os.path.join(Config.SCRIPT_DIR, "adblock_log.txt"))
    SOURCES_FILE: str = field(default_factory=lambda: os.path.join(Config.SCRIPT_DIR, "sources.yaml"))
    OUTPUT_FILE: str = field(default_factory=lambda: os.path.join(Config.SCRIPT_DIR, "adblock_reject.yaml"))
    WHITELIST_FILE: str = field(default_factory=lambda: os.path.join(Config.SCRIPT_DIR, "top_whitelist.txt"))
    REPORT_FILE: str = field(default_factory=lambda: os.path.join(Config.SCRIPT_DIR, "processing_report.json"))
    
    # 网络配置
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    REQUEST_TIMEOUT: int = 20
    MAX_RETRIES: int = 3
    RETRY_DELAY: int = 1
    RETRY_BACKOFF: int = 2
    
    # 并发配置
    MAX_WORKERS: int = 5
    ENABLE_PARALLEL: bool = True
    
    # 域名限制
    DOMAIN_MAX_LENGTH: int = 253
    LABEL_MAX_LENGTH: int = 63
    
    # 时区
    TZ_OFFSET: datetime.timedelta = datetime.timedelta(hours=8)  # UTC+8

# 自定义全局白名单
CUSTOM_EXCLUDED_DOMAINS = [
    # "example.com",
]

# ============================================================================
# 正则表达式引擎
# ============================================================================
class RegexEngine:
    """增强型正则引擎：支持通配符 (*) 提取"""
    
    # 域名验证正则
    DOMAIN_REGEX = re.compile(
        r'^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9.*-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$'
    )
    
    # 规则匹配正则
    REGEX_PATTERNS = {
        'adblock': re.compile(r'^\|\|([a-zA-Z0-9.*-]+)(?:\^.*)?$'),
        'hosts': re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+([a-zA-Z0-9.*-]+)'),
        'dnsmasq': re.compile(r'^(?:address|server)=/([a-zA-Z0-9.*-]+)/'),
        'domain_comma': re.compile(
            r'^(?:DOMAIN|HOST)(?:-SUFFIX|0WILD)?\s*,\s*([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})(?:\s*,.*)?$',
            re.IGNORECASE
        ),
        'plain_domain': re.compile(r'^([a-zA-Z0-9.*-]+)$')
    }
    
    @classmethod
    def is_valid_domain(cls, domain: str) -> bool:
        """验证域名格式"""
        return bool(cls.DOMAIN_REGEX.match(domain))
    
    @classmethod
    def parse_line_to_domain(cls, line: str) -> Optional[str]:
        """从规则行提取域名"""
        if line.startswith("@@"):
            line = line[2:]
        
        domain = None
        for pattern in cls.REGEX_PATTERNS.values():
            if m := pattern.match(line):
                domain = m.group(1)
                break
        
        return domain.strip('.') if domain else None
    
    @staticmethod
    def wildcard_to_regex(domain: str) -> Optional[str]:
        """将通配符域名转换为正则表达式"""
        if '*' not in domain:
            return None
        if domain.startswith('*.') and '*' not in domain[2:]:
            return None
        escaped = re.escape(domain)
        regex_str = escaped.replace(r'\*', '.*')
        return f"^{regex_str}$"

# ============================================================================
# 域名处理器
# ============================================================================
class DomainProcessor:
    """域名处理器"""
    
    def __init__(self):
        self.psl = PublicSuffixList() if PSL_AVAILABLE else None
    
    def is_public_suffix(self, domain: str) -> bool:
        """检查域名是否为公共后缀"""
        if not self.psl:
            return False
        try:
            return self.psl.is_public_suffix(domain)
        except Exception:
            return False
    
    def get_registrable_domain(self, domain: str) -> Optional[str]:
        """获取注册域 (eTLD+1)"""
        if not self.psl:
            return None
        try:
            return self.psl.privatesuffix(domain)
        except Exception:
            return None
    
    @staticmethod
    def get_ancestors(domain: str) -> Set[str]:
        """获取域名的所有祖先域"""
        parts = domain.split('.')
        return {'.'.join(parts[i:]) for i in range(len(parts))}
    
    @staticmethod
    def analyze_domain(domain: str) -> Dict[str, Any]:
        """分析域名结构"""
        parts = domain.split('.')
        return {
            'tld': parts[-1] if parts else 'unknown',
            'level': len(parts),
            'length': len(domain),
            'has_wildcard': '*' in domain,
            'parts': parts
        }

# ============================================================================
# 数据模型
# ============================================================================
@dataclass
class SourceStats:
    """单个源的统计信息"""
    url: str
    status: str = "待处理"
    tier: str = "unknown"
    block_count: int = 0
    allow_count: int = 0
    psl_count: int = 0
    invalid_count: int = 0
    duplicate_count: int = 0
    error_message: str = ""
    processing_time: float = 0.0
    processed_lines: int = 0
    skipped_lines: int = 0

@dataclass
class RuleTypeCount:
    """规则类型统计"""
    domain: int = 0
    domain_suffix: int = 0
    domain_wildcard: int = 0
    domain_regex: int = 0
    
    @property
    def total(self) -> int:
        return self.domain + self.domain_suffix + self.domain_wildcard + self.domain_regex

@dataclass
class ProcessingStats:
    """处理统计主类"""
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    
    # 源统计
    total_sources: int = 0
    successful_sources: int = 0
    failed_sources: int = 0
    source_details: List[SourceStats] = field(default_factory=list)
    
    # 域名统计
    raw_domains: int = 0
    filtered_psl: int = 0
    white_listed: int = 0
    duplicate_removed: int = 0
    invalid_domains: int = 0
    final_domains: int = 0
    
    # 规则统计
    final_rules: RuleTypeCount = field(default_factory=RuleTypeCount)
    
    # 错误跟踪
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # 线程锁
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    
    def add_source(self, stats: SourceStats):
        """添加源统计"""
        with self._lock:
            self.source_details.append(stats)
            if stats.status == "成功":
                self.successful_sources += 1
            else:
                self.failed_sources += 1
    
    def update_domain_stats(self, raw: int = 0, psl: int = 0, 
                           whitelist: int = 0, duplicate: int = 0, 
                           invalid: int = 0, final: int = 0):
        """更新域名统计"""
        with self._lock:
            self.raw_domains += raw
            self.filtered_psl += psl
            self.white_listed += whitelist
            self.duplicate_removed += duplicate
            self.invalid_domains += invalid
            self.final_domains += final
    
    @property
    def elapsed_time(self) -> float:
        """处理耗时（秒）"""
        return (self.end_time or time.time()) - self.start_time
    
    def generate_summary(self) -> str:
        """生成处理摘要"""
        success_rate = (self.successful_sources / max(self.total_sources, 1)) * 100
        dedup_rate = (self.duplicate_removed / max(self.raw_domains, 1)) * 100
        validity_rate = (self.final_domains / max(self.raw_domains, 1)) * 100
        process_speed = self.final_rules.total / max(self.elapsed_time, 0.001)
        
        now = datetime.datetime.now(datetime.timezone.utc) + Config.TZ_OFFSET
        
        return f"""
╔══════════════════════════════════════════════════════════════╗
║               广告拦截规则生成处理报告                       ║
╠══════════════════════════════════════════════════════════════╣
║ 生成时间: {now.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)     ║
║ 总耗时:   {self.elapsed_time:.2f} 秒                      ║
╠══════════════════════════════════════════════════════════════╣
║ 订阅源处理:                                                 ║
║   - 总计: {self.total_sources:>4} 个 (成功率: {success_rate:.1f}%)  ║
║   - 成功: {self.successful_sources:>4} 个                  ║
║   - 失败: {self.failed_sources:>4} 个                      ║
╠══════════════════════════════════════════════════════════════╣
║ 域名处理流程:                                               ║
║   - 原始提取: {self.raw_domains:>6} 个                     ║
║   - 过滤PSL:  {self.filtered_psl:>6} 个                    ║
║   - 白名单:   {self.white_listed:>6} 个                    ║
║   - 去重处理: {self.duplicate_removed:>6} 个 (去重率: {dedup_rate:.1f}%) ║
║   - 无效域名: {self.invalid_domains:>6} 个                 ║
║   - 有效域名: {self.final_domains:>6} 个 (有效率: {validity_rate:.1f}%) ║
╠══════════════════════════════════════════════════════════════╣
║ 规则生成:                                                   ║
║   - DOMAIN:          {self.final_rules.domain:>6} 条       ║
║   - DOMAIN-SUFFIX:   {self.final_rules.domain_suffix:>6} 条       ║
║   - DOMAIN-WILDCARD: {self.final_rules.domain_wildcard:>6} 条       ║
║   - DOMAIN-REGEX:    {self.final_rules.domain_regex:>6} 条       ║
║   - 总计:            {self.final_rules.total:>6} 条       ║
╠══════════════════════════════════════════════════════════════╣
║ 性能指标:                                                   ║
║   - 处理速度: {process_speed:>8.0f} 条/秒                 ║
║   - 峰值内存: {self._get_memory_usage():.1f} MB          ║
╚══════════════════════════════════════════════════════════════╝
"""
    
    @staticmethod
    def _get_memory_usage() -> float:
        """获取当前内存使用（MB）"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0

class StatisticsManager:
    """统计管理器"""
    
    def __init__(self, stats: ProcessingStats):
        self.stats = stats
        self._domain_structure = defaultdict(int)
        self._tld_stats = defaultdict(int)
        self._rule_lengths = []
        self._domain_analyzer = DomainAnalyzer()
    
    def track_domain(self, domain: str):
        """追踪域名特征"""
        analysis = DomainProcessor.analyze_domain(domain)
        
        # 统计TLD分布
        self._tld_stats[analysis['tld']] += 1
        
        # 统计层级分布
        level_name = f"{analysis['level']}级域名"
        self._domain_structure[level_name] += 1
        
        # 记录长度
        self._rule_lengths.append(analysis['length'])
    
    def get_domain_analysis(self) -> Dict[str, Any]:
        """获取域名分析结果"""
        lengths = sorted(self._rule_lengths) if self._rule_lengths else [0]
        
        return {
            'tld_distribution': dict(
                sorted(self._tld_stats.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            'level_distribution': dict(self._domain_structure),
            'length_stats': {
                'average': sum(lengths) / len(lengths),
                'median': lengths[len(lengths) // 2],
                'min': min(lengths),
                'max': max(lengths),
                'total_domains': len(lengths)
            }
        }
    
    def generate_detailed_report(self, output_path: str):
        """生成详细报告（JSON格式）"""
        # 构建源处理详情
        source_reports = []
        for source in self.stats.source_details:
            source_reports.append({
                'url': source.url,
                'tier': source.tier,
                'status': source.status,
                'block_count': source.block_count,
                'allow_count': source.allow_count,
                'psl_filtered': source.psl_count,
                'invalid_domains': source.invalid_count,
                'processing_time': f"{source.processing_time:.2f}s",
                'error': source.error_message if source.error_message else None,
                'lines_processed': source.processed_lines,
                'lines_skipped': source.skipped_lines
            })
        
        # 构建完整报告
        report = {
            'metadata': {
                'generated_at': (datetime.datetime.now(datetime.timezone.utc) + Config.TZ_OFFSET).strftime('%Y-%m-%d %H:%M:%S'),
                'script_version': '2.0.0',
                'processor': 'Mihomo AdBlock Generator'
            },
            'summary': {
                'total_processing_time': f"{self.stats.elapsed_time:.2f}s",
                'total_rules_generated': self.stats.final_rules.total,
                'source_success_rate': f"{(self.stats.successful_sources / max(self.stats.total_sources, 1)) * 100:.1f}%",
                'domain_validity_rate': f"{(self.stats.final_domains / max(self.stats.raw_domains, 1)) * 100:.1f}%",
                'deduplication_rate': f"{(self.stats.duplicate_removed / max(self.stats.raw_domains, 1)) * 100:.1f}%"
            },
            'sources': source_reports,
            'rules_composition': {
                'domain': self.stats.final_rules.domain,
                'domain_suffix': self.stats.final_rules.domain_suffix,
                'domain_wildcard': self.stats.final_rules.domain_wildcard,
                'domain_regex': self.stats.final_rules.domain_regex,
                'total': self.stats.final_rules.total
            },
            'domain_analysis': self.get_domain_analysis(),
            'errors': self.stats.errors[-50:] if self.stats.errors else [],
            'warnings': self.stats.warnings[-50:] if self.stats.warnings else []
        }
        
        # 写入JSON报告
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report

class DomainAnalyzer:
    """域名分析器"""
    
    @staticmethod
    def find_optimization_opportunities(domains: Set[str]) -> List[Dict[str, Any]]:
        """查找可以优化的域名模式"""
        pattern_count = defaultdict(list)
        
        for domain in domains:
            if '*' in domain:
                continue
            
            parts = domain.split('.')
            if len(parts) > 2:
                # 查找可以作为SUFFIX的域名
                suffix_candidate = '.'.join(parts[1:])
                pattern_count[suffix_candidate].append(domain)
        
        opportunities = []
        for suffix, matched_domains in pattern_count.items():
            if len(matched_domains) >= 2:  # 至少2个域名共享相同后缀
                opportunities.append({
                    'suffix': suffix,
                    'count': len(matched_domains),
                    'examples': matched_domains[:5],  # 最多5个示例
                    'suggestion': f'可以使用 DOMAIN-SUFFIX,{suffix} 替代 {len(matched_domains)} 条精确规则'
                })
        
        # 按数量降序排列
        opportunities.sort(key=lambda x: x['count'], reverse=True)
        
        return opportunities[:20]  # 返回前20个优化机会
    
    @staticmethod
    def detect_common_subdomains(domains: Set[str]) -> Dict[str, int]:
        """检测常见子域名模式"""
        subdomain_count = defaultdict(int)
        common_subdomains = ['www', 'api', 'cdn', 'static', 'img', 'images', 
                            'assets', 'media', 'video', 'admin', 'mail', 'smtp']
        
        for domain in domains:
            parts = domain.split('.')
            if len(parts) > 2:
                subdomain = parts[0]
                if subdomain in common_subdomains:
                    subdomain_count[subdomain] += 1
        
        return dict(subdomain_count)

# ============================================================================
# 进度追踪器
# ============================================================================
class ProgressTracker:
    """进度追踪器"""
    
    def __init__(self, total_steps: int, description: str = "处理中"):
        self.total = total_steps
        self.current = 0
        self.description = description
        self.start_time = time.time()
        self._lock = threading.Lock()
        self.last_update = 0
    
    def update(self, step: int = 1, detail: str = ""):
        """更新进度"""
        with self._lock:
            self.current += step
            # 限制更新频率，避免刷屏
            if time.time() - self.last_update >= 0.1 or self.current >= self.total:
                self._display(detail)
                self.last_update = time.time()
    
    def _display(self, detail: str = ""):
        """显示进度条"""
        percent = (self.current / max(self.total, 1)) * 100
        elapsed = time.time() - self.start_time
        eta = (elapsed / max(self.current, 1)) * (self.total - self.current)
        
        bar_length = 40
        filled = int(bar_length * min(self.current / max(self.total, 1), 1))
        bar = '█' * filled + '░' * max(bar_length - filled, 0)
        
        # 格式化时间
        elapsed_str = self._format_time(elapsed)
        eta_str = self._format_time(eta)
        
        status = f'\r{self.description}: |{bar}| {percent:.1f}% ' \
                f'({self.current}/{self.total}) ' \
                f'[⏱ {elapsed_str} | ⏳ {eta_str}]'
        
        if detail:
            status += f' {detail}'
        
        print(status, end='', flush=True)
        
        if self.current >= self.total:
            print()  # 完成时换行
    
    @staticmethod
    def _format_time(seconds: float) -> str:
        """格式化时间显示"""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    def complete(self, message: str = "✓ 完成"):
        """标记完成"""
        with self._lock:
            self.current = self.total
            self._display()
            print(f"\n{message}")

# ============================================================================
# 工具函数
# ============================================================================
class Utils:
    """工具函数集合"""
    
    # 文件编码列表
    COMMON_ENCODINGS = ['utf-8-sig', 'utf-8', 'gbk', 'gb2312', 'latin-1']
    
    @staticmethod
    def write_log(message: str, log_file: str = Config.LOG_FILE):
        """写入日志"""
        print(message)
        time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"{time_str} - {message}\n")
        except Exception as e:
            print(f"警告: 无法写入日志文件: {e}")
    
    @staticmethod
    def smart_decode(data: bytes) -> str:
        """智能解码字节数据"""
        for encoding in Utils.COMMON_ENCODINGS:
            try:
                return data.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        return data.decode('utf-8', errors='ignore')
    
    @staticmethod
    def safe_read_file(file_path: str) -> List[str]:
        """安全读取文件"""
        for encoding in Utils.COMMON_ENCODINGS:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.readlines()
            except (UnicodeDecodeError, FileNotFoundError, LookupError):
                continue
        return []
    
    @staticmethod
    @contextmanager
    def file_writer(file_path: str, mode: str = 'w', encoding: str = 'utf-8'):
        """文件写入上下文管理器"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, mode, encoding=encoding) as f:
                yield f
        except Exception as e:
            print(f"错误: 无法写入文件 {file_path}: {e}")
            yield None
    
    @staticmethod
    def retry(max_attempts: int = Config.MAX_RETRIES, 
              delay: int = Config.RETRY_DELAY, 
              backoff: int = Config.RETRY_BACKOFF):
        """重试装饰器"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                attempts = 0
                last_error = None
                while attempts < max_attempts:
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        attempts += 1
                        last_error = e
                        if attempts == max_attempts:
                            raise last_error
                        sleep_time = delay * (backoff ** (attempts - 1))
                        print(f"  重试 {attempts}/{max_attempts}，等待 {sleep_time} 秒...")
                        time.sleep(sleep_time)
                return None
            return wrapper
        return decorator

# ============================================================================
# 订阅源加载器
# ============================================================================
class SourcesLoader:
    """订阅源加载器"""
    
    @staticmethod
    def load_sources(config_path: str = Config.SOURCES_FILE) -> Dict[str, List[str]]:
        """加载外部订阅源配置"""
        default_sources = {
            "allow_urls": [],
            "tier1_urls": [],
            "tier2_urls": [],
            "tier3_urls": []
        }
        
        if not os.path.exists(config_path):
            Utils.write_log(f"警告: 配置文件 {config_path} 不存在，使用空订阅源")
            return default_sources
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                sources = yaml.safe_load(f)
        except Exception as e:
            Utils.write_log(f"读取配置文件失败: {e}，使用空订阅源")
            return default_sources
        
        # 确保所有键都存在
        for key in default_sources:
            if key not in sources or not isinstance(sources[key], list):
                sources[key] = default_sources[key]
        
        return sources

# ============================================================================
# 规则提取器
# ============================================================================
class RuleExtractor:
    """规则提取器"""
    
    def __init__(self, domain_processor: DomainProcessor, stats: ProcessingStats):
        self.domain_processor = domain_processor
        self.stats = stats
    
    @Utils.retry(max_attempts=Config.MAX_RETRIES)
    def _fetch_url_content(self, url: str) -> Optional[str]:
        """获取URL内容（带重试）"""
        headers = {"User-Agent": Config.USER_AGENT}
        req = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(req, timeout=Config.REQUEST_TIMEOUT) as response:
            return Utils.smart_decode(response.read())
    
    def extract_rules_from_urls(self, urls: List[str], rules_set: Set[str], 
                                global_whitelist: Set[str], tier: str,
                                force_whitelist: bool = False,
                                progress: Optional[ProgressTracker] = None) -> Tuple[int, int, int]:
        """从URL列表提取规则"""
        total_block = 0
        total_allow = 0
        total_psl = 0
        
        Utils.write_log(f"开始处理 {tier} 层的 {len(urls)} 个订阅源...")
        
        for url in urls:
            source_stat = SourceStats(url=url, tier=tier)
            start_time = time.time()
            
            try:
                content = self._fetch_url_content(url)
                if content:
                    block, allow, psl = self._process_content(
                        content, rules_set, global_whitelist, 
                        force_whitelist, source_stat
                    )
                    
                    source_stat.block_count = block
                    source_stat.allow_count = allow
                    source_stat.psl_count = psl
                    source_stat.status = "成功"
                    
                    total_block += block
                    total_allow += allow
                    total_psl += psl
                else:
                    source_stat.status = "失败"
                    source_stat.error_message = "无法获取内容"
                    
            except Exception as e:
                source_stat.status = "失败"
                source_stat.error_message = str(e)
                self.stats.errors.append(f"处理 {url}: {str(e)}")
            
            source_stat.processing_time = time.time() - start_time
            self.stats.add_source(source_stat)
            
            if progress:
                progress.update(1, f"处理: {os.path.basename(url)}")
            
            Utils.write_log(
                f"✔ {source_stat.status}: {url} "
                f"(拦截: {source_stat.block_count}, "
                f"白名单: {source_stat.allow_count}, "
                f"过滤PSL: {source_stat.psl_count})"
            )
        
        return total_block, total_allow, total_psl
    
    def _process_content(self, content: str, rules_set: Set[str], 
                         global_whitelist: Set[str], force_whitelist: bool,
                         source_stat: SourceStats) -> Tuple[int, int, int]:
        """处理源内容"""
        block_cnt = 0
        allow_cnt = 0
        psl_cnt = 0
        lines = content.splitlines()
        
        source_stat.processed_lines = len(lines)
        skipped_lines = 0
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith(("!", "#", "[", ";", "//")):
                skipped_lines += 1
                continue
            
            is_whitelist = force_whitelist or line.startswith("@@")
            domain = RegexEngine.parse_line_to_domain(line)
            
            if not domain or not RegexEngine.is_valid_domain(domain):
                skipped_lines += 1
                continue
            
            domain = domain.lower()
            
            # 过滤公共后缀
            if self.domain_processor.is_public_suffix(domain):
                psl_cnt += 1
                continue
            
            if is_whitelist:
                global_whitelist.add(domain)
                allow_cnt += 1
            else:
                rules_set.add(domain)
                block_cnt += 1
        
        source_stat.skipped_lines = skipped_lines
        source_stat.invalid_count = psl_cnt
        
        return block_cnt, allow_cnt, psl_cnt
    
    def extract_rules_concurrent(self, urls: List[str], rules_set: Set[str], 
                                 global_whitelist: Set[str], tier: str,
                                 force_whitelist: bool = False) -> Tuple[int, int, int]:
        """并发提取规则（实验性功能）"""
        if not Config.ENABLE_PARALLEL or len(urls) <= 1:
            return self.extract_rules_from_urls(urls, rules_set, global_whitelist, tier, force_whitelist)
        
        total_block = 0
        total_allow = 0
        total_psl = 0
        
        Utils.write_log(f"开始并发处理 {tier} 层的 {len(urls)} 个订阅源...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            future_to_url = {
                executor.submit(self._fetch_url_content, url): (url, tier) 
                for url in urls
            }
            
            for future in concurrent.futures.as_completed(future_to_url):
                url, tier = future_to_url[future]
                source_stat = SourceStats(url=url, tier=tier)
                start_time = time.time()
                
                try:
                    content = future.result()
                    if content:
                        block, allow, psl = self._process_content(
                            content, rules_set, global_whitelist, force_whitelist, source_stat
                        )
                        source_stat.block_count = block
                        source_stat.allow_count = allow
                        source_stat.psl_count = psl
                        source_stat.status = "成功"
                        
                        with self.stats._lock:
                            total_block += block
                            total_allow += allow
                            total_psl += psl
                    else:
                        source_stat.status = "失败"
                        source_stat.error_message = "无法获取内容"
                        
                except Exception as e:
                    source_stat.status = "失败"
                    source_stat.error_message = str(e)
                    self.stats.errors.append(f"处理 {url}: {str(e)}")
                
                source_stat.processing_time = time.time() - start_time
                self.stats.add_source(source_stat)
        
        return total_block, total_allow, total_psl

# ============================================================================
# 规则生成器
# ============================================================================
class RuleGenerator:
    """规则生成器 - Mihomo格式"""
    
    def __init__(self, domain_processor: DomainProcessor, stats: ProcessingStats):
        self.domain_processor = domain_processor
        self.stats = stats
        self.stats_manager = StatisticsManager(stats)
    
    def optimize_domains(self, core_rules: Set[str], tier3_rules: Set[str], 
                        white_set: Set[str]) -> Set[str]:
        """优化域名集合"""
        Utils.write_log(">> 正在执行冲突清洗与保护机制校验...")
        
        # 清洗白名单
        valid_core = {d for d in core_rules if d not in white_set}
        
        # 生成保护域
        protected_ancestors = set()
        for domain_set in (white_set, valid_core):
            for domain in domain_set:
                if '*' not in domain:
                    protected_ancestors.update(DomainProcessor.get_ancestors(domain))
        
        # 过滤Tier3
        valid_tier3 = set()
        for domain in tier3_rules:
            if domain in protected_ancestors:
                continue
            valid_tier3.add(domain)
        
        # 合并所有域名
        all_domains = valid_core.union(valid_tier3)
        
        # 子域优化：如果存在父域规则，移除子域规则
        Utils.write_log(">> 正在优化子域名规则...")
        suffix_candidates = {d for d in all_domains if '*' not in d}
        
        global_subs_detector = set()
        for domain in suffix_candidates:
            ancestors = DomainProcessor.get_ancestors(domain)
            # 移除域名本身
            ancestors.discard(domain)
            global_subs_detector.update(ancestors)
        
        optimized_domains = {d for d in all_domains if d not in global_subs_detector}
        
        Utils.write_log(f">> 优化前: {len(all_domains)} 条，优化后: {len(optimized_domains)} 条")
        
        return optimized_domains
    
    def classify_and_format(self, domains: Set[str]) -> List[str]:
        """分类并格式化规则"""
        classified = {
            'domain': [],
            'suffix': [],
            'wildcard': [],
            'regex': []
        }
        
        for domain in sorted(domains):
            # 追踪域名
            self.stats_manager.track_domain(domain)
            
            if '*' in domain:
                # 处理通配符
                if domain.startswith('*.') and '*' not in domain[2:]:
                    classified['wildcard'].append(domain)
                else:
                    regex_pattern = RegexEngine.wildcard_to_regex(domain)
                    if regex_pattern:
                        classified['regex'].append(regex_pattern)
                    else:
                        classified['wildcard'].append(domain)
            elif domain.count('.') >= 4:
                # 深层级域名
                registrable = self.domain_processor.get_registrable_domain(domain)
                if registrable and domain == registrable:
                    classified['suffix'].append(domain)
                else:
                    classified['domain'].append(domain)
            else:
                classified['suffix'].append(domain)
        
        # 构建格式化规则
        formatted_rules = (
            [f"- DOMAIN,{d}" for d in classified['domain']] +
            [f"- DOMAIN-SUFFIX,{d}" for d in classified['suffix']] +
            [f"- DOMAIN-WILDCARD,{d}" for d in classified['wildcard']] +
            [f"- DOMAIN-REGEX,{r}" for r in classified['regex']]
        )
        
        # 更新统计
        self.stats.final_rules = RuleTypeCount(
            domain=len(classified['domain']),
            domain_suffix=len(classified['suffix']),
            domain_wildcard=len(classified['wildcard']),
            domain_regex=len(classified['regex'])
        )
        
        return formatted_rules
    
    def generate_yaml(self, rules: List[str]) -> str:
        """生成YAML内容"""
        generation_time = (datetime.datetime.now(datetime.timezone.utc) + Config.TZ_OFFSET).strftime("%Y-%m-%d %H:%M:%S")
        
        header = f"""# Title: AdBlock_Rule_For_Mihomo
# Generated: {generation_time} (UTC+8)
# Total Items: {len(rules)} 条
# -----------------------------------------------
# 规则分类统计:
# - [DOMAIN]         : {self.stats.final_rules.domain} 条
# - [DOMAIN-SUFFIX]  : {self.stats.final_rules.domain_suffix} 条
# - [DOMAIN-WILDCARD]: {self.stats.final_rules.domain_wildcard} 条
# - [DOMAIN-REGEX]   : {self.stats.final_rules.domain_regex} 条
# -----------------------------------------------

payload:
"""
        return header + "\n".join(rules)

# ============================================================================
# 主程序
# ============================================================================
class AdBlockRuleGenerator:
    """广告拦截规则生成器主类"""
    
    def __init__(self):
        self.config = Config()
        self.stats = ProcessingStats()
        self.domain_processor = DomainProcessor()
        self.rule_extractor = RuleExtractor(self.domain_processor, self.stats)
        self.rule_generator = RuleGenerator(self.domain_processor, self.stats)
        self.stats_manager = StatisticsManager(self.stats)
    
    def run(self):
        """运行规则生成流程"""
        start_time = time.time()
        Utils.write_log("=" * 60)
        Utils.write_log("开始生成 Mihomo 广告拦截规则")
        Utils.write_log("=" * 60)
        
        # 1. 加载配置
        Utils.write_log(">> 正在加载订阅源配置...")
        sources = SourcesLoader.load_sources()
        
        # 计算总源数
        all_urls = (sources['allow_urls'] + sources['tier1_urls'] + 
                   sources['tier2_urls'] + sources['tier3_urls'])
        self.stats.total_sources = len(all_urls)
        
        # 2. 加载白名单
        white_set = self._load_whitelist()
        
        # 3. 提取规则
        Utils.write_log(">> 开始提取规则...")
        progress = ProgressTracker(len(all_urls), "提取规则")
        
        core_set_raw = set()
        tier3_set_raw = set()
        
        # 提取allow_urls（全局白名单）
        block1, allow1, psl1 = self.rule_extractor.extract_rules_from_urls(
            sources['allow_urls'], core_set_raw, white_set, 
            tier="ALLOW", force_whitelist=True, progress=progress
        )
        
        # 提取tier1和tier2（核心拦截规则）
        tier12_urls = sources['tier1_urls'] + sources['tier2_urls']
        block2, allow2, psl2 = self.rule_extractor.extract_rules_from_urls(
            tier12_urls, core_set_raw, white_set, 
            tier="TIER1+2", progress=progress
        )
        
        # 提取tier3（次要规则）
        block3, allow3, psl3 = self.rule_extractor.extract_rules_from_urls(
            sources['tier3_urls'], tier3_set_raw, white_set, 
            tier="TIER3", progress=progress
        )
        
        progress.complete("✓ 规则提取完成")
        
        # 4. 更新统计
        raw_total = block1 + block2 + block3 + allow1 + allow2 + allow3
        self.stats.update_domain_stats(
            raw=raw_total,
            psl=psl1 + psl2 + psl3,
            whitelist=allow1 + allow2 + allow3,
            duplicate=0  # 将在优化阶段计算
        )
        
        # 5. 优化域名
        Utils.write_log(">> 开始域名优化...")
        optimized_domains = self.rule_generator.optimize_domains(
            core_set_raw, tier3_set_raw, white_set
        )
        
        # 计算去重数量
        total_before_optimize = len(core_set_raw) + len(tier3_set_raw)
        self.stats.duplicate_removed = max(0, total_before_optimize - len(optimized_domains))
        self.stats.final_domains = len(optimized_domains)
        
        # 6. 格式化和分类规则
        Utils.write_log(">> 正在格式化规则...")
        formatted_rules = self.rule_generator.classify_and_format(optimized_domains)
        
        # 7. 生成YAML输出
        Utils.write_log(">> 正在生成YAML输出...")
        yaml_content = self.rule_generator.generate_yaml(formatted_rules)
        
        output_path = Config.OUTPUT_FILE
        with Utils.file_writer(output_path) as f:
            f.write(yaml_content)
        
        Utils.write_log(f"✓ 成功导出 {len(formatted_rules)} 条规则至: {output_path}")
        
        # 8. 完成统计
        self.stats.end_time = time.time()
        
        # 9. 生成报告
        self._generate_reports()
        
        # 10. 显示摘要
        print(self.stats.generate_summary())
        
        Utils.write_log("=" * 60)
        Utils.write_log("规则生成完成！")
        Utils.write_log("=" * 60)
        
        return output_path
    
    def _load_whitelist(self) -> Set[str]:
        """加载白名单"""
        white_set = set(d.lower() for d in CUSTOM_EXCLUDED_DOMAINS)
        
        # 加载本地高权重白名单
        whitelist_file = Config.WHITELIST_FILE
        if os.path.exists(whitelist_file):
            loaded_count = 0
            for line in Utils.safe_read_file(whitelist_file):
                line = line.strip()
                if not line or line.startswith(("!", "#", "[", ";", "//")):
                    continue
                domain = RegexEngine.parse_line_to_domain(line)
                if domain and RegexEngine.is_valid_domain(domain):
                    domain = domain.lower()
                    if not self.domain_processor.is_public_suffix(domain):
                        white_set.add(domain)
                        loaded_count += 1
            
            Utils.write_log(f"已加载本地白名单 {loaded_count} 条，总计 {len(white_set)} 条。")
        else:
            Utils.write_log("未找到本地白名单文件。")
        
        self.stats.white_listed = len(white_set)
        return white_set
    
    def _generate_reports(self):
        """生成各类报告"""
        # 生成JSON详细报告
        self.stats_manager.generate_detailed_report(Config.REPORT_FILE)
        Utils.write_log(f"✓ 详细报告已生成: {Config.REPORT_FILE}")
        
        # 分析优化机会
        # 注意：这里需要访问optimized_domains，但在当前架构中需要调整
        # 这部分可作为后续增强功能

# ============================================================================
# 命令行入口
# ============================================================================
def main():
    """主函数"""
    try:
        generator = AdBlockRuleGenerator()
        output_path = generator.run()
        
        print(f"\n✓ 规则文件已生成: {output_path}")
        print(f"✓ 详细报告已生成: {Config.REPORT_FILE}")
        
        return 0
    except KeyboardInterrupt:
        print("\n\n✖ 用户中断操作")
        return 1
    except Exception as e:
        print(f"\n✖ 发生错误: {e}")
        import traceback
        traceback.print_exc()
        return 2

if __name__ == "__main__":
    sys.exit(main())
