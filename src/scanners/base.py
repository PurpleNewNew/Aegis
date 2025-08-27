"""Aegis模块化漏洞扫描器架构
提供基于插件的漏洞检测系统
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Type, Union
from dataclasses import dataclass
from enum import Enum
import asyncio
import logging
import importlib

from playwright.async_api import Page, Request, Response

# 假设AI客户端可以通过某种方式获取，这里用一个placeholder
# 在实际应用中，这应该通过依赖注入传入
class AIClientPlaceholder:
    async def query(self, prompt: str, json_mode: bool = True) -> Dict[str, Any]:
        logger.info("正在使用AI客户端查询（占位符）...")
        # 返回一个模拟的AI响应，用于演示
        await asyncio.sleep(0.1)
        return {
            "vulnerability_detected": True,
            "confidence": "Medium",
            "reasoning": "AI分析占位符：检测到用户输入被直接用于innerHTML。",
            "source": "some_variable",
            "sink": ".innerHTML"
        }

ai_client = AIClientPlaceholder()
logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    XSS = "xss"
    SSTI = "ssti"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    SECRET_LEAKAGE = "secret_leakage"
    INSECURE_CRYPTO = "insecure_crypto"
    CSRF = "csrf"
    SSRF = "ssrf"
    JS_REVERSE = "js_reverse"
    AUTH_BYPASS = "auth_bypass"


class SeverityLevel(Enum):
    """漏洞严重级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """漏洞发现数据结构"""
    vuln_type: VulnerabilityType
    name: str
    description: str
    severity: SeverityLevel
    confidence: str
    location: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    references: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ScanContext:
    """漏洞扫描上下文"""
    url: str
    page: Optional[Page] = None
    request: Optional[Request] = None
    response: Optional[Response] = None
    source_code: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, Any]] = None
    cookies: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ScanResult:
    """漏洞扫描结果"""
    scanner_id: str
    vulnerabilities: List[Vulnerability]
    errors: List[str]
    execution_time: float
    metadata: Optional[Dict[str, Any]] = None


class BaseScanner(ABC):
    """所有漏洞扫描器的基类"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)
        self.scanner_id = self.__class__.__name__
        self.logger = logging.getLogger(f"{__name__}.{self.scanner_id}")
        
    @property
    @abstractmethod
    def name(self) -> str: pass
        
    @property
    @abstractmethod
    def description(self) -> str: pass
        
    @property
    @abstractmethod
    def vuln_types(self) -> List[VulnerabilityType]: pass
        
    @abstractmethod
    async def scan(self, context: ScanContext) -> ScanResult: pass
        
    async def is_applicable(self, context: ScanContext) -> bool:
        return True
        
    def create_vulnerability(self, **kwargs) -> Vulnerability:
        return Vulnerability(**kwargs)


class SASTScanner(BaseScanner):
    """静态应用安全测试扫描器的基类"""
    @property
    def category(self) -> str: return "sast"
    async def is_applicable(self, context: ScanContext) -> bool: return context.source_code is not None


class DASTScanner(BaseScanner):
    """动态应用安全测试扫描器的基类"""
    @property
    def category(self) -> str: return "dast"
    async def is_applicable(self, context: ScanContext) -> bool: return context.url is not None


# --- 新增AI扫描器相关基类 ---
class AIBaseScanner(BaseScanner):
    """能够调用AI进行分析的扫描器基类"""

    @property
    @abstractmethod
    def prompt_name(self) -> str:
        """返回此扫描器使用的提示词模块名 (例如 'xss')"""
        pass

    async def analyze_with_ai(self, ai_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """使用模块化提示词和AI客户端进行分析的通用方法"""
        try:
            # 1. 动态加载提示词模块
            prompt_module_name = f"src.prompts.{self.prompt_name}_prompts"
            prompt_module = importlib.import_module(prompt_module_name)
            
            # 2. 获取提示词生成函数并创建提示词
            get_prompt_func = getattr(prompt_module, 'get_analysis_prompt')
            prompt = get_prompt_func(ai_context)
            
            # 3. 使用AI客户端进行查询
            self.logger.info(f"调用AI对 {self.prompt_name} 进行分析...")
            ai_result = await ai_client.query(prompt, json_mode=True)
            
            if ai_result and ai_result.get('vulnerability_detected'):
                self.logger.info(f"AI在 {self.prompt_name} 分析中发现潜在漏洞。")
                return ai_result
            else:
                self.logger.info(f"AI在 {self.prompt_name} 分析中未发现漏洞。")
                return None

        except ImportError:
            self.logger.error(f"无法加载提示词模块: {prompt_module_name}")
            return None
        except AttributeError:
            self.logger.error(f"在 {prompt_module_name} 中未找到 get_analysis_prompt 函数。")
            return None
        except Exception as e:
            self.logger.error(f"AI分析过程中发生错误: {e}", exc_info=True)
            return None

class AISASTScanner(AIBaseScanner, SASTScanner):
    """结合了AI能力的SAST扫描器"""
    pass
# --------------------------

class ScannerRegistry:
    """管理漏洞扫描器的注册器"""
    
    def __init__(self):
        self._scanners: Dict[str, Type[BaseScanner]] = {}
        self._instances: Dict[str, BaseScanner] = {}
        self._scanner_configs: Dict[str, Dict[str, Any]] = {}
        
    def register(self, scanner_class: Type[BaseScanner], config: Optional[Dict[str, Any]] = None) -> None:
        scanner_id = scanner_class.__name__
        self._scanners[scanner_id] = scanner_class
        if config:
            self._scanner_configs[scanner_id] = config
        logger.info(f"已注册扫描器: {scanner_id}")
        
    def unregister(self, scanner_id: str) -> None:
        if scanner_id in self._scanners:
            del self._scanners[scanner_id]
            if scanner_id in self._instances: del self._instances[scanner_id]
            if scanner_id in self._scanner_configs: del self._scanner_configs[scanner_id]
            logger.info(f"已注销扫描器: {scanner_id}")
            
    def get_scanner(self, scanner_id: str) -> Optional[BaseScanner]:
        if scanner_id not in self._scanners: return None
        if scanner_id not in self._instances:
            scanner_class = self._scanners[scanner_id]
            config = self._scanner_configs.get(scanner_id, {})
            self._instances[scanner_id] = scanner_class(config)
        return self._instances[scanner_id]
        
    def list_scanners(self) -> List[str]:
        return list(self._scanners.keys())
        
    def get_scanners_by_type(self, vuln_type: VulnerabilityType) -> List[BaseScanner]:
        scanners = []
        for scanner_id in self._scanners:
            scanner = self.get_scanner(scanner_id)
            if scanner and scanner.enabled and vuln_type in scanner.vuln_types:
                scanners.append(scanner)
        return scanners


class ScanOrchestrator:
    """编排多个漏洞扫描器"""
    
    def __init__(self, registry: 'ScannerRegistry', max_concurrent: int = 5):
        self.registry = registry
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.logger = logging.getLogger(__name__)
        
    async def scan_all(self, context: ScanContext, scanner_ids: Optional[List[str]] = None, vuln_types: Optional[List[VulnerabilityType]] = None) -> List[ScanResult]:
        scanners_to_run = []
        if scanner_ids:
            for scanner_id in scanner_ids:
                scanner = self.registry.get_scanner(scanner_id)
                if scanner: scanners_to_run.append(scanner)
        elif vuln_types:
            for vuln_type in vuln_types:
                scanners = self.registry.get_scanners_by_type(vuln_type)
                scanners_to_run.extend(scanners)
        else:
            for scanner_id in self.registry.list_scanners():
                scanner = self.registry.get_scanner(scanner_id)
                if scanner and await scanner.is_applicable(context):
                    scanners_to_run.append(scanner)
                    
        scanners_to_run = list({s.scanner_id: s for s in scanners_to_run}.values())
        if not scanners_to_run: return []
            
        self.logger.info(f"正在对 {context.url} 运行 {len(scanners_to_run)} 个扫描器")
        tasks = [asyncio.create_task(self._run_scanner_with_semaphore(scanner, context)) for scanner in scanners_to_run]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        scan_results = []
        for i, result in enumerate(results):
            if isinstance(result, ScanResult):
                scan_results.append(result)
            elif isinstance(result, Exception):
                scanner_id = scanners_to_run[i].scanner_id
                self.logger.error(f"扫描器 {scanner_id} 失败: {result}")
                scan_results.append(ScanResult(scanner_id=scanner_id, vulnerabilities=[], errors=[str(result)], execution_time=0))
        return scan_results
        
    async def _run_scanner_with_semaphore(self, scanner: BaseScanner, context: ScanContext) -> ScanResult:
        async with self.semaphore:
            start_time = asyncio.get_event_loop().time()
            try:
                self.logger.debug(f"运行扫描器: {scanner.scanner_id}")
                result = await scanner.scan(context)
                result.execution_time = asyncio.get_event_loop().time() - start_time
                self.logger.debug(f"扫描器 {scanner.scanner_id} 在 {result.execution_time:.2f}s 内完成")
                return result
            except Exception as e:
                execution_time = asyncio.get_event_loop().time() - start_time
                self.logger.error(f"扫描器 {scanner.scanner_id} 在 {execution_time:.2f}s 后失败: {e}")
                return ScanResult(scanner_id=scanner.scanner_id, vulnerabilities=[], errors=[str(e)], execution_time=execution_time)


registry = ScannerRegistry()