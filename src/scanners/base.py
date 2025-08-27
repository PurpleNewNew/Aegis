"""Aegis模块化漏洞扫描器架构
提供基于插件的漏洞检测系统
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Type, Union
from dataclasses import dataclass
from enum import Enum
import asyncio
import logging
from playwright.async_api import Page, Request, Response

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
    confidence: str  # "确定", "高", "中", "低"
    location: str  # URL或文件路径
    evidence: str  # 漏洞证据
    remediation: str  # 修复建议
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
    def name(self) -> str:
        """可读的扫描器名称"""
        pass
        
    @property
    @abstractmethod
    def description(self) -> str:
        """扫描器描述"""
        pass
        
    @property
    @abstractmethod
    def vuln_types(self) -> List[VulnerabilityType]:
        """此扫描器能检测的漏洞类型列表"""
        pass
        
    @abstractmethod
    async def scan(self, context: ScanContext) -> ScanResult:
        """
        执行漏洞扫描
        
        Args:
            context: 包含目标信息的扫描上下文
            
        Returns:
            包含发现和错误的ScanResult
        """
        pass
        
    async def is_applicable(self, context: ScanContext) -> bool:
        """
        检查此扫描器是否适用于给定的上下文
        
        Args:
            context: 扫描上下文
            
        Returns:
            如果应该运行扫描器则返回True
        """
        # 默认实现 - 可以被重写
        return True
        
    def create_vulnerability(
        self,
        vuln_type: VulnerabilityType,
        name: str,
        description: str,
        severity: SeverityLevel,
        confidence: str = "medium",
        location: str = "",
        evidence: str = "",
        remediation: str = "",
        **kwargs
    ) -> Vulnerability:
        """创建漏洞对象的辅助方法"""
        return Vulnerability(
            vuln_type=vuln_type,
            name=name,
            description=description,
            severity=severity,
            confidence=confidence,
            location=location,
            evidence=evidence,
            remediation=remediation,
            **kwargs
        )


class SASTScanner(BaseScanner):
    """静态应用安全测试扫描器的基类"""
    
    @property
    def category(self) -> str:
        return "sast"
        
    async def is_applicable(self, context: ScanContext) -> bool:
        return context.source_code is not None


class DASTScanner(BaseScanner):
    """动态应用安全测试扫描器的基类"""
    
    @property
    def category(self) -> str:
        return "dast"
        
    async def is_applicable(self, context: ScanContext) -> bool:
        return context.url is not None


class IASTScanner(BaseScanner):
    """交互式应用安全测试扫描器的基类"""
    
    @property
    def category(self) -> str:
        return "iast"
        
    async def is_applicable(self, context: ScanContext) -> bool:
        return context.page is not None


class ScannerRegistry:
    """管理漏洞扫描器的注册器"""
    
    def __init__(self):
        self._scanners: Dict[str, Type[BaseScanner]] = {}
        self._instances: Dict[str, BaseScanner] = {}
        self._scanner_configs: Dict[str, Dict[str, Any]] = {}
        
    def register(self, scanner_class: Type[BaseScanner], config: Optional[Dict[str, Any]] = None) -> None:
        """
        注册扫描器类
        
        Args:
            scanner_class: 要注册的扫描器类
            config: 扫描器配置
        """
        scanner_id = scanner_class.__name__
        self._scanners[scanner_id] = scanner_class
        if config:
            self._scanner_configs[scanner_id] = config
        logger.info(f"已注册扫描器: {scanner_id}")
        
    def unregister(self, scanner_id: str) -> None:
        """注销扫描器"""
        if scanner_id in self._scanners:
            del self._scanners[scanner_id]
            if scanner_id in self._instances:
                del self._instances[scanner_id]
            if scanner_id in self._scanner_configs:
                del self._scanner_configs[scanner_id]
            logger.info(f"已注销扫描器: {scanner_id}")
            
    def get_scanner(self, scanner_id: str) -> Optional[BaseScanner]:
        """获取扫描器实例"""
        if scanner_id not in self._scanners:
            return None
            
        if scanner_id not in self._instances:
            scanner_class = self._scanners[scanner_id]
            config = self._scanner_configs.get(scanner_id, {})
            self._instances[scanner_id] = scanner_class(config)
            
        return self._instances[scanner_id]
        
    def list_scanners(self) -> List[str]:
        """列出所有已注册的扫描器ID"""
        return list(self._scanners.keys())
        
    def get_scanners_by_type(self, vuln_type: VulnerabilityType) -> List[BaseScanner]:
        """获取能检测特定漏洞类型的所有扫描器"""
        scanners = []
        for scanner_id in self._scanners:
            scanner = self.get_scanner(scanner_id)
            if scanner and scanner.enabled and vuln_type in scanner.vuln_types:
                scanners.append(scanner)
        return scanners
        
    def get_scanners_by_category(self, category: str) -> List[BaseScanner]:
        """获取特定类别中的所有扫描器"""
        scanners = []
        for scanner_id in self._scanners:
            scanner = self.get_scanner(scanner_id)
            if scanner and scanner.enabled and hasattr(scanner, 'category') and scanner.category == category:
                scanners.append(scanner)
        return scanners


class ScanOrchestrator:
    """编排多个漏洞扫描器"""
    
    def __init__(self, registry: ScannerRegistry, max_concurrent: int = 5):
        self.registry = registry
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.logger = logging.getLogger(__name__)
        
    async def scan_all(
        self, 
        context: ScanContext,
        scanner_ids: Optional[List[str]] = None,
        vuln_types: Optional[List[VulnerabilityType]] = None
    ) -> List[ScanResult]:
        """
        对目标运行多个扫描器
        
        Args:
            context: 扫描上下文
            scanner_ids: 要运行的特定扫描器（可选）
            vuln_types: 只运行这些漏洞类型的扫描器（可选）
            
        Returns:
            扫描结果列表
        """
        # 确定要运行的扫描器
        scanners_to_run = []
        
        if scanner_ids:
            # 运行特定扫描器
            for scanner_id in scanner_ids:
                scanner = self.registry.get_scanner(scanner_id)
                if scanner:
                    scanners_to_run.append(scanner)
        elif vuln_types:
            # 运行特定漏洞类型的扫描器
            for vuln_type in vuln_types:
                scanners = self.registry.get_scanners_by_type(vuln_type)
                scanners_to_run.extend(scanners)
        else:
            # 运行所有适用的扫描器
            for scanner_id in self.registry.list_scanners():
                scanner = self.registry.get_scanner(scanner_id)
                if scanner and await scanner.is_applicable(context):
                    scanners_to_run.append(scanner)
                    
        # 去重
        scanners_to_run = list({s.scanner_id: s for s in scanners_to_run}.values())
        
        if not scanners_to_run:
            self.logger.warning("未找到适用的扫描器")
            return []
            
        self.logger.info(f"正在对 {context.url} 运行 {len(scanners_to_run)} 个扫描器")
        
        # 使用信号量并发运行扫描器
        tasks = []
        for scanner in scanners_to_run:
            task = asyncio.create_task(self._run_scanner_with_semaphore(scanner, context))
            tasks.append(task)
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理结果
        scan_results = []
        for i, result in enumerate(results):
            if isinstance(result, ScanResult):
                scan_results.append(result)
            elif isinstance(result, Exception):
                scanner_id = scanners_to_run[i].scanner_id
                self.logger.error(f"扫描器 {scanner_id} 失败: {result}")
                scan_results.append(ScanResult(
                    scanner_id=scanner_id,
                    vulnerabilities=[],
                    errors=[str(result)],
                    execution_time=0
                ))
                
        return scan_results
        
    async def _run_scanner_with_semaphore(self, scanner: BaseScanner, context: ScanContext) -> ScanResult:
        """使用信号量控制运行单个扫描器"""
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
                return ScanResult(
                    scanner_id=scanner.scanner_id,
                    vulnerabilities=[],
                    errors=[str(e)],
                    execution_time=execution_time
                )


# 全局注册器实例
registry = ScannerRegistry()