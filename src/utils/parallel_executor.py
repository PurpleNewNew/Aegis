import asyncio
import logging
import json
from typing import List, Dict, Any, Optional, Tuple
from playwright.async_api import Page, BrowserContext

class ParallelTaskExecutor:
    """并行任务执行器，用于协调多个影子浏览器的并行测试"""
    
    def __init__(self, pages: List[Page], config: dict):
        self.pages = pages
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.active_tasks = {}
        
    async def execute_parallel_tasks(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        并行执行多个测试任务
        
        Args:
            tasks: 任务列表，每个任务包含:
                - name: 任务名称
                - action: 要执行的操作
                - target_page: 目标页面ID (可选，默认分配)
                - params: 操作参数
                
        Returns:
            执行结果列表
        """
        if not tasks:
            return []
            
        # 分配任务到页面
        assigned_tasks = self._assign_tasks_to_pages(tasks)
        
        # 并行执行任务
        results = []
        for page_id, page_tasks in assigned_tasks.items():
            if page_id <= len(self.pages):
                page = self.pages[page_id - 1]
                page_results = await self._execute_tasks_on_page(page, page_tasks, page_id)
                results.extend(page_results)
        
        return results
    
    def _assign_tasks_to_pages(self, tasks: List[Dict[str, Any]]) -> Dict[int, List[Dict]]:
        """将任务分配到可用的页面"""
        assigned = {}
        page_count = len(self.pages)
        
        for i, task in enumerate(tasks):
            # 如果指定了目标页面，使用指定页面
            if 'target_page' in task:
                page_id = task['target_page']
                if 1 <= page_id <= page_count:
                    assigned.setdefault(page_id, []).append(task)
                else:
                    # 如果指定页面无效，分配到第一个页面
                    assigned.setdefault(1, []).append(task)
            else:
                # 轮询分配
                page_id = (i % page_count) + 1
                assigned.setdefault(page_id, []).append(task)
        
        return assigned
    
    async def _execute_tasks_on_page(self, page: Page, tasks: List[Dict], page_id: int) -> List[Dict]:
        """在单个页面上执行多个任务"""
        results = []
        
        self.logger.info(f"在影子浏览器 {page_id} 上执行 {len(tasks)} 个任务")
        
        for task in tasks:
            try:
                result = await self._execute_single_task(page, task, page_id)
                results.append(result)
            except Exception as e:
                self.logger.error(f"在页面 {page_id} 上执行任务失败: {e}")
                results.append({
                    'task': task.get('name', 'unknown'),
                    'success': False,
                    'error': str(e),
                    'page_id': page_id
                })
        
        return results
    
    async def _execute_single_task(self, page: Page, task: Dict, page_id: int) -> Dict:
        """执行单个任务"""
        task_name = task.get('name', 'unknown')
        action = task.get('action')
        params = task.get('params', {})
        
        self.logger.info(f"执行任务 '{task_name}' on 影子浏览器 {page_id}")
        
        # 根据动作类型执行不同的操作
        if action == 'click':
            element = params.get('element')
            if element:
                await page.click(element, timeout=5000)
                return {
                    'task': task_name,
                    'success': True,
                    'action': 'click',
                    'element': element,
                    'page_id': page_id
                }
        
        elif action == 'fill':
            element = params.get('element')
            value = params.get('value')
            if element and value:
                await page.fill(element, value, timeout=5000)
                return {
                    'task': task_name,
                    'success': True,
                    'action': 'fill',
                    'element': element,
                    'value': value,
                    'page_id': page_id
                }
        
        elif action == 'navigate':
            url = params.get('url')
            if url:
                await page.goto(url, timeout=10000)
                return {
                    'task': task_name,
                    'success': True,
                    'action': 'navigate',
                    'url': url,
                    'page_id': page_id
                }
        
        elif action == 'screenshot':
            screenshot = await page.screenshot(full_page=True)
            return {
                'task': task_name,
                'success': True,
                'action': 'screenshot',
                'screenshot_size': len(screenshot),
                'page_id': page_id
            }
        
        elif action == 'evaluate':
            script = params.get('script')
            if script:
                result = await page.evaluate(script)
                return {
                    'task': task_name,
                    'success': True,
                    'action': 'evaluate',
                    'result': result,
                    'page_id': page_id
                }
        
        else:
            return {
                'task': task_name,
                'success': False,
                'error': f'Unknown action: {action}',
                'page_id': page_id
            }

class SmartParallelOrchestrator:
    """智能并行编排器，让AI决定如何使用多个影子浏览器"""
    
    def __init__(self, agent_worker):
        self.agent_worker = agent_worker
        self.logger = logging.getLogger(self.__class__.__name__)
        
    async def create_parallel_strategy(self, page_analysis: Dict, available_browsers: int) -> Dict[str, Any]:
        """
        基于页面分析创建并行测试策略
        
        Args:
            page_analysis: 页面分析结果
            available_browsers: 可用的浏览器数量
            
        Returns:
            并行策略字典
        """
        # 使用AI分析页面，决定如何分配任务
        prompt = f"""
        基于以下页面分析，设计一个使用 {available_browsers} 个影子浏览器的并行测试策略：
        
        页面URL: {page_analysis.get('url', 'N/A')}
        页面标题: {page_analysis.get('title', 'N/A')}
        页面内容预览: {page_analysis.get('content_preview', 'N/A')[:500]}...
        发现的表单: {json.dumps(page_analysis.get('forms', []), indent=2)}
        发现的链接: {len(page_analysis.get('links', []))} 个
        发现的按钮: {len(page_analysis.get('buttons', []))} 个
        
        请设计一个并行测试策略，考虑：
        1. 哪些功能点可以并行测试
        2. 如何分配浏览器以达到最佳效率
        3. 需要多少个浏览器同时工作
        
        以JSON格式返回策略，包含：
        - parallel_tasks: 并行任务列表
        - browser_allocation: 浏览器分配方案
        - expected_benefits: 预期收益
        """
        
        try:
            # 调用LLM生成策略
            llm_config = self.agent_worker.config['llm_service']
            messages = [
                {"role": "system", "content": "你是一个专业的Web安全测试专家，擅长设计并行测试策略。"},
                {"role": "user", "content": prompt}
            ]
            
            response = await self.agent_worker.llm_client.chat.completions.create(
                model=llm_config['api_config']['model_name'],
                messages=messages,
                temperature=0.7,
                max_tokens=1500
            )
            
            content = response.choices[0].message.content
            
            # 解析JSON响应
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0].strip()
            
            strategy = json.loads(content)
            self.logger.info(f"AI生成了并行测试策略，使用 {len(strategy.get('parallel_tasks', []))} 个并行任务")
            return strategy
            
        except Exception as e:
            self.logger.error(f"生成并行策略失败: {e}")
            # 返回默认策略
            return {
                'parallel_tasks': [],
                'browser_allocation': {},
                'expected_benefits': 'Failed to generate strategy'
            }