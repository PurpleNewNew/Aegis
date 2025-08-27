"""
Aegis框架的自定义异常类
提供特定的异常类型以实现更好的错误处理
"""


class AegisError(Exception):
    """Aegis框架的基础异常类"""
    pass


class ConfigurationError(AegisError):
    """配置相关错误"""
    pass


class BrowserConnectionError(AegisError):
    """浏览器连接相关错误"""
    pass


class ResourceError(AegisError):
    """资源管理相关错误"""
    pass


class SecurityError(AegisError):
    """安全相关错误"""
    pass


class ValidationError(AegisError):
    """输入验证错误"""
    pass


class NetworkError(AegisError):
    """网络相关错误"""
    pass


class AIError(AegisError):
    """AI服务相关错误"""
    pass