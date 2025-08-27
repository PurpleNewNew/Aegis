"""
Security utilities for Aegis framework
Provides path validation, input sanitization, and other security helpers
"""

import os
import re
import urllib.parse
from pathlib import Path
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class SecurityUtils:
    """Security utility functions for path validation and input sanitization"""
    
    # Allowed file extensions for safe file operations
    ALLOWED_EXTENSIONS = {
        '.json', '.jsonl', '.yaml', '.yml', '.txt', '.md', '.log', '.html', '.js'
    }
    
    # Safe directories for file operations
    SAFE_BASE_DIRS = [
        'reports', 'logs', 'chroma_db', 'config.yaml', 'requirements.txt'
    ]
    
    @staticmethod
    def validate_file_path(file_path: str, base_dir: Optional[str] = None) -> str:
        """
        Validate and sanitize file paths to prevent directory traversal attacks
        
        Args:
            file_path: The file path to validate
            base_dir: Optional base directory to restrict access to
            
        Returns:
            Absolute, sanitized file path
            
        Raises:
            ValueError: If path is invalid or potentially malicious
        """
        if not file_path:
            raise ValueError("File path cannot be empty")
        
        # Normalize path to remove '..' and resolve symlinks
        try:
            # Convert to absolute path
            abs_path = os.path.abspath(os.path.normpath(file_path))
            
            # Check for path traversal attempts
            if '..' in file_path or file_path.startswith('~'):
                raise ValueError("Path traversal detected")
                
            # Check file extension
            file_ext = Path(abs_path).suffix.lower()
            if file_ext and file_ext not in SecurityUtils.ALLOWED_EXTENSIONS:
                raise ValueError(f"File extension {file_ext} not allowed")
                
            # If base_dir is specified, ensure path is within it
            if base_dir:
                base_abs = os.path.abspath(base_dir)
                if not abs_path.startswith(base_abs):
                    raise ValueError("File path outside allowed directory")
            else:
                # Check if path is within safe directories
                in_safe_dir = False
                for safe_dir in SecurityUtils.SAFE_BASE_DIRS:
                    safe_abs = os.path.abspath(safe_dir)
                    if abs_path.startswith(safe_abs):
                        in_safe_dir = True
                        break
                
                if not in_safe_dir:
                    raise ValueError("File path not in allowed directory")
            
            return abs_path
            
        except (OSError, ValueError) as e:
            logger.error(f"Path validation failed for {file_path}: {e}")
            raise ValueError(f"Invalid file path: {e}")
    
    @staticmethod
    def validate_url(url: str) -> str:
        """
        Validate and sanitize URLs
        
        Args:
            url: URL to validate
            
        Returns:
            Sanitized URL
            
        Raises:
            ValueError: If URL is invalid or potentially malicious
        """
        if not url:
            raise ValueError("URL cannot be empty")
        
        try:
            # Parse URL
            parsed = urllib.parse.urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                raise ValueError("Only HTTP/HTTPS URLs are allowed")
                
            # Check for potentially dangerous characters
            dangerous_chars = ['<', '>', '"', "'", '`', ' ', '\n', '\r', '\t']
            if any(char in url for char in dangerous_chars):
                raise ValueError("URL contains dangerous characters")
                
            # Reconstruct URL to ensure it's properly formatted
            safe_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            return safe_url
            
        except Exception as e:
            logger.error(f"URL validation failed for {url}: {e}")
            raise ValueError(f"Invalid URL: {e}")
    
    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 1000) -> str:
        """
        Sanitize user input to prevent injection attacks
        
        Args:
            input_str: Input string to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not input_str:
            return ""
        
        # Truncate to max length
        sanitized = input_str[:max_length]
        
        # Remove potentially dangerous characters
        dangerous_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'expression\s*\(',
        ]
        
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        return sanitized.strip()
    
    @staticmethod
    def create_safe_directory(dir_path: str) -> None:
        """
        Safely create a directory with proper permissions
        
        Args:
            dir_path: Directory path to create
        """
        try:
            # Validate path first
            safe_path = SecurityUtils.validate_file_path(dir_path)
            
            # Create directory with restrictive permissions
            os.makedirs(safe_path, mode=0o750, exist_ok=True)
            logger.info(f"Created safe directory: {safe_path}")
            
        except Exception as e:
            logger.error(f"Failed to create directory {dir_path}: {e}")
            raise


class ConfigValidator:
    """Configuration validation schema"""
    
    REQUIRED_FIELDS = {
        'browser': ['remote_debugging_port'],
        'scanner_scope': ['whitelist_domains'],
        'llm_service': ['api_config'],
    }
    
    PORT_RANGE = (1024, 65535)
    
    @classmethod
    def validate_config(cls, config: dict) -> List[str]:
        """
        Validate configuration dictionary
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check required fields
        for section, fields in cls.REQUIRED_FIELDS.items():
            if section not in config:
                errors.append(f"Missing configuration section: {section}")
                continue
                
            for field in fields:
                if field not in config[section]:
                    errors.append(f"Missing required field: {section}.{field}")
        
        # Validate specific fields
        if 'browser' in config:
            cls._validate_browser_config(config['browser'], errors)
            
        if 'scanner_scope' in config:
            cls._validate_scanner_config(config['scanner_scope'], errors)
            
        if 'llm_service' in config:
            cls._validate_llm_config(config['llm_service'], errors)
        
        return errors
    
    @classmethod
    def _validate_browser_config(cls, browser_config: dict, errors: List[str]) -> None:
        """Validate browser configuration"""
        if 'remote_debugging_port' in browser_config:
            port = browser_config['remote_debugging_port']
            if not isinstance(port, int) or not (cls.PORT_RANGE[0] <= port <= cls.PORT_RANGE[1]):
                errors.append(f"Invalid remote debugging port: {port}")
    
    @classmethod
    def _validate_scanner_config(cls, scanner_config: dict, errors: List[str]) -> None:
        """Validate scanner scope configuration"""
        if 'whitelist_domains' in scanner_config:
            domains = scanner_config['whitelist_domains']
            if not isinstance(domains, list) or not domains:
                errors.append("whitelist_domains must be a non-empty list")
    
    @classmethod
    def _validate_llm_config(cls, llm_config: dict, errors: List[str]) -> None:
        """Validate LLM service configuration"""
        if 'api_config' in llm_config:
            api_config = llm_config['api_config']
            required_api_fields = ['base_url', 'model_name']
            
            for field in required_api_fields:
                if field not in api_config:
                    errors.append(f"Missing LLM API field: {field}")
                elif not isinstance(api_config[field], str) or not api_config[field]:
                    errors.append(f"LLM API field {field} must be a non-empty string")