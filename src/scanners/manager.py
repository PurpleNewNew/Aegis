"""扫描器管理器 - 管理和编排漏洞扫描器
"""

import asyncio
import logging
import os
import importlib
import inspect
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from .base import BaseScanner, ScanOrchestrator, registry, ScanContext, ScanResult, VulnerabilityType


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
        
        if config.auto_register:
            self._auto_register_scanners()
            
    def _auto_register_scanners(self) -> None:
        """(V2) 动态发现并注册在配置中启用的扫描器"""
        if not self.config.enabled_scanners:
            self.logger.warning("配置中未启用任何扫描器 (scanners.enabled)，将不会注册任何扫描器。")
            return

        self.logger.info(f"正在从配置中加载启用的扫描器: {self.config.enabled_scanners}")
        scanner_dir = os.path.dirname(__file__)
        registered_count = 0

        for module_name in self.config.enabled_scanners:
            module_path = os.path.join(scanner_dir, f"{module_name}.py")
            if not os.path.exists(module_path):
                self.logger.warning(f"跳过扫描器 '{module_name}'，因为未找到对应的文件: {module_path}")
                continue
            
            try:
                module_spec = importlib.util.spec_from_file_location(f"src.scanners.{module_name}", module_path)
                scanner_module = importlib.util.module_from_spec(module_spec)
                module_spec.loader.exec_module(scanner_module)
            except Exception as e:
                self.logger.error(f"动态导入扫描器模块 '{module_name}' 失败: {e}", exc_info=True)
                continue

            for name, obj in inspect.getmembers(scanner_module):
                if inspect.isclass(obj) and issubclass(obj, BaseScanner) and obj is not BaseScanner and not inspect.isabstract(obj):
                    scanner_class = obj
                    scanner_name = scanner_class.__name__
                    
                    # 从主配置中获取该扫描器的特定配置
                    scanner_specific_config = (self.config.scanner_configs or {}).get(scanner_name, {})
                    
                    registry.register(scanner_class, scanner_specific_config)
                    registered_count += 1
        
        self.logger.info(f"动态注册了 {registered_count} 个扫描器。")
        
    async def scan_target(
        self,
        context: ScanContext,
        scanner_ids: Optional[List[str]] = None,
        vuln_types: Optional[List[VulnerabilityType]] = None
    ) -> List[ScanResult]:
        """
        扫描目标与指定的扫描器
        """
        self.logger.info(f"开始扫描 {context.url}")
        
        if scanner_ids:
            self.logger.info(f"运行特定扫描器: {', '.join(scanner_ids)}")
        elif vuln_types:
            vuln_names = [v.value for v in vuln_types]
            self.logger.info(f"运行漏洞类型的扫描器: {', '.join(vuln_names)}")
        else:
            self.logger.info("运行所有已启用的适用扫描器")
            
        results = await self.orchestrator.scan_all(context, scanner_ids, vuln_types)
        
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
        """
        self.logger.info(f"开始批量扫描 {len(contexts)} 个目标")
        tasks = []
        for context in contexts:
            task = asyncio.create_task(
                self.scan_target(context, scanner_ids, vuln_types)
            )
            tasks.append((context.url, task))
            
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
        """列出所有已注册的扫描器及其信息"""
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


def create_scanner_manager(config: Dict[str, Any]) -> ScannerManager:
    """从主配置字典创建扫描器管理器"""
    # 提取扫描器相关的配置
    scanner_main_config = config.get('scanners', {})
    
    scanner_config_obj = ScannerConfig(
        max_concurrent_scans=scanner_main_config.get('max_concurrent_scans', 5),
        enabled_scanners=scanner_main_config.get('enabled'),
        scanner_configs=scanner_main_config.get('configs', {}),
        auto_register=scanner_main_config.get('auto_register', True)
    )
    
    return ScannerManager(scanner_config_obj)
