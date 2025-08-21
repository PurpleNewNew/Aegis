"""
共享状态管理器 - 在规划者和执行者之间共享信息
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class SharedState:
    """
    在AgentWorker之间共享的状态信息
    
    这个类充当了一个"黑板"，各个组件可以读写信息。
    """
    
    # 基础信息
    current_url: str = ""
    goal: str = ""
    
    # 计划相关
    current_plan: List[str] = field(default_factory=list)
    plan_index: int = 0
    
    # 执行历史
    action_history: List[str] = field(default_factory=list)
    
    # 页面状态
    page_content: str = ""
    interactive_elements: List[Dict] = field(default_factory=list)
    
    # 网络捕获
    captured_requests: List[Dict[str, Any]] = field(default_factory=list)
    is_capturing_network: bool = False
    
    # 发现的问题
    findings: List[Dict[str, Any]] = field(default_factory=list)
    
    # 认证状态
    auth_state: Optional[Dict[str, Any]] = None
    
    def get_current_task(self) -> Optional[str]:
        """获取当前要执行的任务"""
        if self.plan_index < len(self.current_plan):
            return self.current_plan[self.plan_index]
        return None
    
    def advance_plan(self):
        """前进到下一个任务"""
        self.plan_index += 1
        
    def is_plan_complete(self) -> bool:
        """检查计划是否已完成"""
        return self.plan_index >= len(self.current_plan)
    
    def reset_plan(self):
        """重置计划执行状态"""
        self.plan_index = 0
        self.current_plan = []
        
    def add_action(self, action: str):
        """记录执行的动作"""
        self.action_history.append(f"{datetime.now().isoformat()}: {action}")
        
    def add_finding(self, vulnerability: str, description: str, severity: str, details: Dict[str, Any]):
        """添加发现的问题"""
        self.findings.append({
            "vulnerability": vulnerability,
            "description": description,
            "severity": severity,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })
        
    def update_page_state(self, recon_data: Dict[str, Any]):
        """更新页面状态信息"""
        if "page_content" in recon_data:
            self.page_content = recon_data["page_content"]
        if "interactive_elements" in recon_data:
            self.interactive_elements = recon_data["interactive_elements"]
            
    def start_network_capture(self):
        """标记开始网络捕获"""
        self.captured_requests = []
        
    def stop_network_capture(self, requests: List[Dict[str, Any]]):
        """停止网络捕获并保存结果"""
        self.captured_requests = requests
        
    def get_context_summary(self) -> str:
        """获取当前状态的摘要（用于日志或调试）"""
        summary = f"""
=== 共享状态摘要 ===
URL: {self.current_url}
目标: {self.goal}
当前计划: {self.current_plan}
计划进度: {self.plan_index}/{len(self.current_plan)}
已执行动作: {len(self.action_history)}
发现问题: {len(self.findings)}
网络捕获中: {self.is_capturing_network}
捕获请求数: {len(self.captured_requests)}
==================
"""
        return summary
    
    def export_findings(self) -> Dict[str, Any]:
        """导出所有发现的问题"""
        return {
            "url": self.current_url,
            "goal": self.goal,
            "timestamp": datetime.now().isoformat(),
            "total_actions": len(self.action_history),
            "findings": self.findings,
            "network_analysis": {
                "total_requests_captured": len(self.captured_requests),
                "requests": self.captured_requests[:10]  # 只导出前10个请求
            }
        }
        
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于序列化）"""
        return {
            "current_url": self.current_url,
            "goal": self.goal,
            "current_plan": self.current_plan,
            "plan_index": self.plan_index,
            "action_history": self.action_history[-20:],  # 只保留最近20条
            "findings": self.findings,
            "is_capturing_network": self.is_capturing_network
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SharedState":
        """从字典创建实例"""
        state = cls()
        for key, value in data.items():
            if hasattr(state, key):
                setattr(state, key, value)
        return state
