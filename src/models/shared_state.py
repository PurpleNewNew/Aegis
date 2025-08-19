"""
共享状态管理器 - 在规划者和执行者之间共享信息
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import json


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
    plan_created_at: Optional[datetime] = None
    
    # 执行历史
    action_history: List[str] = field(default_factory=list)
    tool_call_history: List[Dict[str, Any]] = field(default_factory=list)
    
    # 页面状态
    page_content: str = ""
    interactive_elements: List[Dict] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    current_page_title: str = ""
    
    # 网络捕获
    captured_requests: List[Dict[str, Any]] = field(default_factory=list)
    is_capturing_network: bool = False
    capture_start_time: Optional[datetime] = None
    
    # 发现的问题
    findings: List[Dict[str, Any]] = field(default_factory=list)
    potential_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    
    # 认证状态（用于shared模式）
    auth_state: Optional[Dict[str, Any]] = None
    cookies: List[Dict] = field(default_factory=list)
    local_storage: Dict[str, str] = field(default_factory=dict)
    session_storage: Dict[str, str] = field(default_factory=dict)
    
    # 错误和重试
    error_count: int = 0
    last_error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    
    # JavaScript执行结果缓存
    js_execution_cache: Dict[str, Any] = field(default_factory=dict)
    
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
        self.plan_created_at = None
        
    def add_action(self, action: str):
        """记录执行的动作"""
        self.action_history.append(f"{datetime.now().isoformat()}: {action}")
        
    def add_tool_call(self, tool_name: str, args: Dict, result: Any):
        """记录工具调用"""
        self.tool_call_history.append({
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "args": args,
            "result": result
        })
        
    def add_finding(self, finding_type: str, description: str, severity: str = "info", evidence: Any = None):
        """添加发现的问题"""
        finding = {
            "type": finding_type,
            "description": description,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "url": self.current_url,
            "evidence": evidence
        }
        self.findings.append(finding)
        
        # 如果是潜在漏洞，也加入漏洞列表
        if severity in ["high", "critical"]:
            self.potential_vulnerabilities.append(finding)
            
    def update_page_state(self, recon_data: Dict[str, Any]):
        """更新页面状态信息"""
        if "page_content" in recon_data:
            self.page_content = recon_data["page_content"]
        if "interactive_elements" in recon_data:
            self.interactive_elements = recon_data["interactive_elements"]
        if "forms" in recon_data:
            self.forms = recon_data["forms"]
        if "title" in recon_data:
            self.current_page_title = recon_data["title"]
            
    def start_network_capture(self):
        """标记开始网络捕获"""
        self.is_capturing_network = True
        self.capture_start_time = datetime.now()
        self.captured_requests = []
        
    def stop_network_capture(self, requests: List[Dict[str, Any]]):
        """停止网络捕获并保存结果"""
        self.is_capturing_network = False
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
潜在漏洞: {len(self.potential_vulnerabilities)}
网络捕获中: {self.is_capturing_network}
捕获请求数: {len(self.captured_requests)}
错误次数: {self.error_count}
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
            "vulnerabilities": self.potential_vulnerabilities,
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
            "potential_vulnerabilities": self.potential_vulnerabilities,
            "error_count": self.error_count,
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
