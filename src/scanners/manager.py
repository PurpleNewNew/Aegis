"""扫描器管理器 - 管理和编排漏洞扫描器
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from . import ScanOrchestrator, registry, ScanContext, ScanResult, VulnerabilityType


@dataclass
class ScannerConfig:
    """扫描器管理器配置"""
    max_concurrent_scans: int = 5
    enabled_scanners: Optional[List[str]] = None
    scanner_configs: Optional[Dict[str, Dict[str, Any]]] = None
    auto_register: bool = True


class ScannerManager:
    """管理漏洞扫描操作"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.orchestrator = ScanOrchestrator(registry, config.max_concurrent_scans)
        self.logger = logging.getLogger(__name__)
        
        # 如果启用则自动注册扫描器
        if config.auto_register:
            self._auto_register_scanners()
            
    def _auto_register_scanners(self) -> None:
        """自动注册扫描器及其配置"""
        scanner_configs = self.config.scanner_configs or {}
        
        # 导入所有扫描器类
        from . import XSSStaticScanner, XSSDynamicScanner, SSTIScanner, JSReverseScanner
        
        # 注册扫描器及其配置
        scanners_to_register = [
            XSSStaticScanner,
            XSSDynamicScanner,
            SSTIScanner,
            JSReverseScanner,
        ]
        
        for scanner_class in scanners_to_register:
            scanner_name = scanner_class.__name__
            config = scanner_configs.get(scanner_name, {})
            
            # 检查扫描器是否启用
            if self.config.enabled_scanners and scanner_name not in self.config.enabled_scanners:
                config['enabled'] = False
                
            registry.register(scanner_class, config)
            
        self.logger.info(f"自动注册了 {len(scanners_to_register)} 个扫描器")
        
    async def scan_target(
        self,
        context: ScanContext,
        scanner_ids: Optional[List[str]] = None,
        vuln_types: Optional[List[VulnerabilityType]] = None
    ) -> List[ScanResult]:
        """
        扫描目标与指定的扫描器
        
        Args:
            context: 包含目标信息的扫描上下文
            scanner_ids: 要运行的特定扫描器（可选）
            vuln_types: 仅运行这些漏洞类型的扫描器（可选）
            
        Returns:
            扫描结果列表
        """
        self.logger.info(f"开始扫描 {context.url}")
        
        # 如果请求了特定扫描器，则使用它们
        if scanner_ids:
            self.logger.info(f"运行特定扫描器: {', '.join(scanner_ids)}")
        elif vuln_types:
            vuln_names = [v.value for v in vuln_types]
            self.logger.info(f"运行漏洞类型的扫描器: {', '.join(vuln_names)}")
        else:
            self.logger.info("运行所有适用的扫描器")
            
        # 运行扫描
        results = await self.orchestrator.scan_all(context, scanner_ids, vuln_types)
        
        # 记录摘要
        total_vulns = sum(len(r.vulnerabilities) for r in results)
        total_errors = sum(len(r.errors) for r in results)
        
        self.logger.info(f"扫描完成: 发现 {total_vulns} 个漏洞, {total_errors} 个错误")
        
        return results
        
    async def scan_multiple_targets(
        self,
        contexts: List[ScanContext],
        scanner_ids: Optional[List[str]] = None,
        vuln_types: Optional[List[VulnerabilityType]] = None
    ) -> Dict[str, List[ScanResult]]:
        """
        扫描多个目标
        
        Args:
            contexts: 扫描上下文列表
            scanner_ids: 要运行的特定扫描器（可选）
            vuln_types: 仅运行这些漏洞类型的扫描器（可选）
            
        Returns:
            将URL映射到扫描结果的字典
        """
        self.logger.info(f"开始批量扫描 {len(contexts)} 个目标")
        
        # 创建扫描任务
        tasks = []
        for context in contexts:
            task = asyncio.create_task(
                self.scan_target(context, scanner_ids, vuln_types)
            )
            tasks.append((context.url, task))
            
        # 等待所有扫描完成
        results = {}
        for url, task in tasks:
            try:
                scan_results = await task
                results[url] = scan_results
            except Exception as e:
                self.logger.error(f"{url} 的扫描失败: {e}")
                results[url] = []
                
        return results
        
    def list_available_scanners(self) -> List[Dict[str, Any]]:
        """列出所有可用的扫描器及其信息"""
        scanners = []
        
        for scanner_id in registry.list_scanners():
            scanner = registry.get_scanner(scanner_id)
            if scanner:
                scanners.append({
                    'id': scanner_id,
                    'name': scanner.name,
                    'description': scanner.description,
                    'vuln_types': [v.value for v in scanner.vuln_types],
                    'enabled': scanner.enabled,
                    'category': getattr(scanner, 'category', 'unknown')
                })
                
        return scanners
        
    def get_scanner_by_vuln_type(self, vuln_type: VulnerabilityType) -> List[str]:
        """获取能检测特定漏洞类型的所有扫描器ID"""
        scanners = registry.get_scanners_by_type(vuln_type)
        return [s.scanner_id for s in scanners if s.enabled]
        
    def get_scanner_by_category(self, category: str) -> List[str]:
        """获取特定类别中的所有扫描器ID"""
        scanners = registry.get_scanners_by_category(category)
        return [s.scanner_id for s in scanners if s.enabled]


def create_scanner_manager(config: Dict[str, Any]) -> ScannerManager:
    """从配置字典创建扫描器管理器"""
    scanner_config = ScannerConfig(
        max_concurrent_scans=config.get('max_concurrent_scans', 5),
        enabled_scanners=config.get('enabled_scanners'),
        scanner_configs=config.get('scanner_configs', {}),
        auto_register=config.get('auto_register', True)
    )
    
    return ScannerManager(scanner_config)