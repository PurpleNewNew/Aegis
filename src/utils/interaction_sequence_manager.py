import asyncio
import logging
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict
import time

logger = logging.getLogger(__name__)

class InteractionSequenceManager:
    """交互序列管理器，处理操作依赖关系和执行顺序"""
    
    def __init__(self):
        self.sequences = {}  # url -> interaction sequence
        self.dependencies = defaultdict(set)  # interaction_id -> dependent_ids
        self.execution_order = []  # 执行顺序
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def add_interaction(self, url: str, interaction: Dict[str, Any]) -> str:
        """添加交互事件到序列"""
        interaction_id = interaction.get('id', f"{int(time.time()*1000)}")
        interaction['id'] = interaction_id
        
        if url not in self.sequences:
            self.sequences[url] = []
        
        self.sequences[url].append(interaction)
        
        # 分析依赖关系
        self._analyze_dependencies(interaction)
        
        return interaction_id
    
    def get_sequence_for_url(self, url: str) -> List[Dict[str, Any]]:
        """获取指定URL的交互序列"""
        return self.sequences.get(url, [])
    
    def get_execution_order(self, url: str) -> List[Dict[str, Any]]:
        """获取执行顺序（考虑依赖关系）"""
        sequence = self.get_sequence_for_url(url)
        if not sequence:
            return []
        
        # 拓扑排序
        return self._topological_sort(sequence)
    
    def _analyze_dependencies(self, interaction: Dict[str, Any]):
        """分析交互之间的依赖关系"""
        interaction_type = interaction.get('type')
        interaction_id = interaction.get('id')
        
        # 基于交互类型的依赖规则
        dependencies = set()
        
        # 输入操作通常依赖于之前的焦点操作
        if interaction_type == 'input':
            # 查找同一元素的focus事件
            selector = interaction.get('element', {}).get('selector')
            if selector:
                for prev_interaction in self._get_previous_interactions(interaction):
                    if (prev_interaction.get('type') == 'focus' and 
                        prev_interaction.get('element', {}).get('selector') == selector):
                        dependencies.add(prev_interaction.get('id'))
        
        # 提交操作依赖于所有输入操作
        elif interaction_type == 'submit':
            form_selector = interaction.get('element', {}).get('selector')
            if form_selector:
                # 查找表单内的所有输入操作
                for prev_interaction in self._get_previous_interactions(interaction):
                    if (prev_interaction.get('type') in ['input', 'change'] and
                        self._is_element_in_form(prev_interaction.get('element', {}).get('selector'), form_selector)):
                        dependencies.add(prev_interaction.get('id'))
        
        # 点击操作可能依赖于输入操作
        elif interaction_type == 'click':
            selector = interaction.get('element', {}).get('selector')
            if selector:
                # 查找同一元素或相关元素的输入操作
                for prev_interaction in self._get_previous_interactions(interaction):
                    if (prev_interaction.get('type') == 'input' and
                        self._are_elements_related(prev_interaction.get('element', {}).get('selector'), selector)):
                        dependencies.add(prev_interaction.get('id'))
        
        # 添加依赖关系
        self.dependencies[interaction_id] = dependencies
    
    def _get_previous_interactions(self, interaction: Dict[str, Any]) -> List[Dict[str, Any]]:
        """获取指定交互之前的所有交互"""
        url = interaction.get('pageState', {}).get('url')
        timestamp = interaction.get('timestamp', 0)
        
        sequence = self.get_sequence_for_url(url)
        return [i for i in sequence if i.get('timestamp', 0) < timestamp and i.get('id') != interaction.get('id')]
    
    def _is_element_in_form(self, element_selector: str, form_selector: str) -> bool:
        """检查元素是否在表单内"""
        # 简化实现：检查选择器层级关系
        return element_selector and form_selector and element_selector.startswith(form_selector)
    
    def _are_elements_related(self, selector1: str, selector2: str) -> bool:
        """检查两个元素是否相关"""
        if not selector1 or not selector2:
            return False
        
        # 如果是同一个元素
        if selector1 == selector2:
            return True
        
        # 检查是否是父子关系
        return selector1.startswith(selector2) or selector2.startswith(selector1)
    
    def _topological_sort(self, sequence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """拓扑排序，确定执行顺序"""
        # 构建图
        graph = defaultdict(list)
        in_degree = {}
        
        for interaction in sequence:
            interaction_id = interaction.get('id')
            in_degree[interaction_id] = 0
        
        for interaction in sequence:
            interaction_id = interaction.get('id')
            deps = self.dependencies.get(interaction_id, set())
            
            for dep_id in deps:
                if dep_id in in_degree:
                    graph[dep_id].append(interaction_id)
                    in_degree[interaction_id] += 1
        
        # 拓扑排序
        queue = [interaction_id for interaction_id, degree in in_degree.items() if degree == 0]
        result = []
        
        while queue:
            current_id = queue.pop(0)
            
            # 找到对应的交互
            for interaction in sequence:
                if interaction.get('id') == current_id:
                    result.append(interaction)
                    break
            
            # 更新入度
            for neighbor_id in graph[current_id]:
                in_degree[neighbor_id] -= 1
                if in_degree[neighbor_id] == 0:
                    queue.append(neighbor_id)
        
        # 检查是否有环
        if len(result) != len(sequence):
            self.logger.warning("检测到循环依赖，使用原始顺序")
            return sequence
        
        return result
    
    def get_interaction_chain_until_commit(self, url: str, commit_interaction_id: str) -> List[Dict[str, Any]]:
        """获取直到提交操作的完整交互链"""
        execution_order = self.get_execution_order(url)
        chain = []
        
        for interaction in execution_order:
            chain.append(interaction)
            if interaction.get('id') == commit_interaction_id:
                break
        
        return chain
    
    def clear_sequence(self, url: str):
        """清除指定URL的交互序列"""
        if url in self.sequences:
            del self.sequences[url]
        
        # 清除相关依赖
        ids_to_remove = []
        for interaction_id in self.dependencies:
            if any(interaction.get('pageState', {}).get('url') == url 
                   for interaction in self.sequences.get(url, [])):
                ids_to_remove.append(interaction_id)
        
        for interaction_id in ids_to_remove:
            del self.dependencies[interaction_id]

class InteractionValidator:
    """交互验证器，确保操作可以安全复现"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    async def validate_sequence(self, sequence: List[Dict[str, Any]], page) -> Dict[str, Any]:
        """验证交互序列是否可以安全复现"""
        validation_result = {
            'valid': True,
            'warnings': [],
            'errors': [],
            'recommendations': []
        }
        
        # 检查每个交互
        for i, interaction in enumerate(sequence):
            interaction_type = interaction.get('type')
            element_info = interaction.get('element', {})
            selector = element_info.get('selector')
            
            # 检查选择器是否有效
            if not selector:
                validation_result['warnings'].append(f"步骤 {i+1}: 缺少选择器")
                continue
            
            # 检查元素是否存在
            try:
                element = page.locator(selector)
                count = await element.count()
                
                if count == 0:
                    validation_result['errors'].append(f"步骤 {i+1}: 找不到元素 {selector}")
                    validation_result['valid'] = False
                elif count > 1:
                    validation_result['warnings'].append(f"步骤 {i+1}: 选择器匹配到多个元素 ({count}个)")
                    
            except Exception as e:
                validation_result['errors'].append(f"步骤 {i+1}: 检查元素时出错 {e}")
                validation_result['valid'] = False
            
            # 特定验证
            if interaction_type == 'input':
                # 检查输入框是否可编辑
                try:
                    is_editable = await page.evaluate(f"""() => {{
                        const el = document.querySelector('{selector}');
                        return el && !el.readOnly && !el.disabled;
                    }}""")
                    
                    if not is_editable:
                        validation_result['errors'].append(f"步骤 {i+1}: 输入框不可编辑")
                        validation_result['valid'] = False
                        
                except Exception as e:
                    validation_result['warnings'].append(f"步骤 {i+1}: 无法验证输入框状态 {e}")
            
            elif interaction_type == 'click':
                # 检查按钮是否可点击
                try:
                    is_clickable = await page.evaluate(f"""() => {{
                        const el = document.querySelector('{selector}');
                        return el && !el.disabled && el.offsetParent !== null;
                    }}""")
                    
                    if not is_clickable:
                        validation_result['warnings'].append(f"步骤 {i+1}: 元素可能不可点击")
                        
                except Exception as e:
                    validation_result['warnings'].append(f"步骤 {i+1}: 无法验证点击状态 {e}")
        
        return validation_result