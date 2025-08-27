import asyncio
import logging
from typing import List, Dict, Any, Optional
from playwright.async_api import Page, Error as PlaywrightError

logger = logging.getLogger(__name__)

class InteractionReplayer:
    """增强的交互复现器，支持完整的操作序列复现"""
    
    def __init__(self, page: Page, config: dict = None):
        self.page = page
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.interaction_sequence = []
        self.current_step = 0
        self.wait_after_action = self.config.get('wait_after_action', 0.5)
        self.max_retries = self.config.get('max_retries', 3)
        
    async def load_sequence(self, sequence: List[Dict[str, Any]]):
        """加载交互序列"""
        self.interaction_sequence = sequence
        self.current_step = 0
        self.logger.info(f"加载了 {len(sequence)} 个交互操作")
        
    async def replay_sequence(self, from_step: int = 0) -> bool:
        """完整复现交互序列"""
        if not self.interaction_sequence:
            self.logger.warning("没有可复现的交互序列")
            return False
            
        self.logger.info(f"开始复现交互序列（从步骤 {from_step} 开始）")
        
        # 从指定步骤开始复现
        for i in range(from_step, len(self.interaction_sequence)):
            self.current_step = i
            interaction = self.interaction_sequence[i]
            
            try:
                success = await self._replay_single_interaction(interaction, i)
                if not success:
                    self.logger.error(f"步骤 {i+1} 复现失败，停止复现")
                    return False
                    
            except Exception as e:
                self.logger.error(f"复现步骤 {i+1} 时发生错误: {e}")
                return False
        
        self.logger.info("交互序列复现完成")
        return True
    
    async def _replay_single_interaction(self, interaction: Dict[str, Any], step_index: int) -> bool:
        """复现单个交互操作"""
        interaction_type = interaction.get('type')
        element_info = interaction.get('element', {})
        details = interaction.get('details', {})
        
        self.logger.info(f"复现步骤 {step_index + 1}: {interaction_type}")
        
        # 等待元素出现
        selector = element_info.get('selector')
        if not selector:
            self.logger.warning(f"步骤 {step_index + 1}: 没有选择器，跳过")
            return True
            
        # 等待元素可交互
        if not await self._wait_for_element(selector):
            self.logger.error(f"步骤 {step_index + 1}: 无法找到元素 {selector}")
            return False
        
        # 根据交互类型执行相应操作
        try:
            if interaction_type == 'click':
                return await self._replay_click(selector, details)
            elif interaction_type == 'input':
                return await self._replay_input(selector, element_info, details)
            elif interaction_type == 'keydown':
                return await self._replay_keydown(selector, details)
            elif interaction_type == 'focus':
                return await self._replay_focus(selector)
            elif interaction_type == 'change':
                return await self._replay_change(selector, element_info, details)
            elif interaction_type == 'submit':
                return await self._replay_submit(selector, details)
            else:
                self.logger.warning(f"未支持的交互类型: {interaction_type}")
                return True
                
        except Exception as e:
            self.logger.error(f"执行 {interaction_type} 时出错: {e}")
            return False
    
    async def _wait_for_element(self, selector: str, timeout: int = 10000) -> bool:
        """等待元素出现并可交互"""
        try:
            element = self.page.locator(selector)
            await element.wait_for(state='visible', timeout=timeout)
            await element.wait_for(state='enabled', timeout=5000)
            return True
        except:
            return False
    
    async def _replay_click(self, selector: str, details: Dict) -> bool:
        """复现点击操作"""
        for attempt in range(self.max_retries):
            try:
                element = self.page.locator(selector)
                
                # 检查是否在视口中
                is_visible = await element.is_visible()
                if not is_visible:
                    await element.scroll_into_view_if_needed()
                    await asyncio.sleep(0.5)
                
                # 执行点击
                await element.click(timeout=5000)
                
                # 等待可能的页面变化
                await asyncio.sleep(self.wait_after_action)
                
                self.logger.debug(f"成功点击: {selector}")
                return True
                
            except PlaywrightError as e:
                if attempt < self.max_retries - 1:
                    self.logger.warning(f"点击失败（尝试 {attempt + 1}/{self.max_retries}）: {e}")
                    await asyncio.sleep(1)
                else:
                    # 尝试JavaScript点击
                    try:
                        await self.page.evaluate(f"document.querySelector('{selector}').click()")
                        await asyncio.sleep(self.wait_after_action)
                        self.logger.debug(f"使用JavaScript成功点击: {selector}")
                        return True
                    except:
                        self.logger.error(f"所有点击尝试都失败了: {selector}")
                        return False
    
    async def _replay_input(self, selector: str, element_info: Dict, details: Dict) -> bool:
        """复现输入操作"""
        value = element_info.get('value', '')
        input_type = details.get('inputType', 'insertText')
        
        try:
            element = self.page.locator(selector)
            
            # 先清空输入框
            await element.clear()
            await asyncio.sleep(0.2)
            
            # 根据输入类型处理
            if input_type == 'insertText':
                # 模拟真实输入
                for char in value:
                    await element.press(char)
                    await asyncio.sleep(0.05)  # 模拟输入间隔
            elif input_type == 'deleteContentBackward':
                # 处理删除操作
                pass  # 已经清空了
            else:
                # 直接设置值
                await element.fill(value)
            
            await asyncio.sleep(self.wait_after_action)
            self.logger.debug(f"成功输入到 {selector}: {value[:20]}{'...' if len(value) > 20 else ''}")
            return True
            
        except Exception as e:
            self.logger.error(f"输入失败: {e}")
            return False
    
    async def _replay_keydown(self, selector: str, details: Dict) -> bool:
        """复现键盘事件"""
        key = details.get('key', '')
        
        try:
            element = self.page.locator(selector)
            
            # 特殊键处理
            if key in ['Enter', 'Tab', 'Escape']:
                await element.press(key)
            else:
                await element.type(key)
            
            await asyncio.sleep(0.2)
            self.logger.debug(f"成功按键 {key} on {selector}")
            return True
            
        except Exception as e:
            self.logger.error(f"按键失败: {e}")
            return False
    
    async def _replay_focus(self, selector: str) -> bool:
        """复现焦点事件"""
        try:
            element = self.page.locator(selector)
            await element.focus()
            await asyncio.sleep(0.1)
            return True
        except Exception as e:
            self.logger.error(f"设置焦点失败: {e}")
            return False
    
    async def _replay_change(self, selector: str, element_info: Dict, details: Dict) -> bool:
        """复现change事件"""
        try:
            element = self.page.locator(selector)
            
            # 对于下拉框
            if element_info.get('tagName') == 'select':
                value = element_info.get('value')
                await element.select_option(value)
            else:
                value = element_info.get('value', '')
                await element.fill(value)
            
            await asyncio.sleep(self.wait_after_action)
            return True
        except Exception as e:
            self.logger.error(f"change事件失败: {e}")
            return False
    
    async def _replay_submit(self, selector: str, details: Dict) -> bool:
        """复现表单提交"""
        try:
            form = self.page.locator(selector)
            await form.evaluate("form => form.submit()")
            
            # 等待导航完成
            await self.page.wait_for_load_state('networkidle', timeout=10000)
            await asyncio.sleep(self.wait_after_action)
            
            return True
        except Exception as e:
            self.logger.error(f"表单提交失败: {e}")
            return False
    
    async def save_page_state(self) -> Dict[str, Any]:
        """保存当前页面状态"""
        try:
            return {
                url: self.page.url,
                title: await self.page.title(),
                cookies: await self.page.context.cookies(),
                localStorage: await self.page.evaluate("() => ({...localStorage})"),
                sessionStorage: await self.page.evaluate("() => ({...sessionStorage})")
            }
        except Exception as e:
            self.logger.error(f"保存页面状态失败: {e}")
            return {}
    
    async def restore_page_state(self, state: Dict[str, Any]) -> bool:
        """恢复页面状态"""
        try:
            # 恢复cookies
            if state.get('cookies'):
                await self.page.context.add_cookies(state['cookies'])
            
            # 恢复storage
            if state.get('localStorage'):
                await self.page.evaluate("(storage) => { for (let [k, v] of Object.entries(storage)) localStorage.setItem(k, v) }", state['localStorage'])
            
            if state.get('sessionStorage'):
                await self.page.evaluate("(storage) => { for (let [k, v] of Object.entries(storage)) sessionStorage.setItem(k, v) }", state['sessionStorage'])
            
            return True
        except Exception as e:
            self.logger.error(f"恢复页面状态失败: {e}")
            return False