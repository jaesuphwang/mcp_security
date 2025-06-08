# Copyright 2025 Jae Sup Hwang
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Comprehensive input validation and sanitization module.
"""
import re
import html
import urllib.parse
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, validator, constr, conint
import bleach
from core.utils.logging import get_logger

logger = get_logger(__name__)

# Security constants
MAX_STRING_LENGTH = 10000
MAX_ARRAY_LENGTH = 1000
MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_HTML_TAGS = []  # No HTML tags allowed by default
SQL_INJECTION_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b)",
    r"(--|\||;|\/\*|\*\/)",
    r"(\bOR\b\s*\d+\s*=\s*\d+)",
    r"(\bAND\b\s*\d+\s*=\s*\d+)",
]
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe[^>]*>",
    r"<object[^>]*>",
]
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\%2[fF]/",
    r"\%2[eE]\%2[eE]/",
    r"\.\.\\",
    r"\.\.\%5[cC]",
]

class InputValidator:
    """Comprehensive input validation class."""
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = MAX_STRING_LENGTH) -> str:
        """Sanitize string input."""
        if not isinstance(value, str):
            raise ValueError(f"Expected string, got {type(value)}")
        
        # Truncate to max length
        value = value[:max_length]
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # HTML escape
        value = html.escape(value)
        
        # Remove any HTML tags
        value = bleach.clean(value, tags=ALLOWED_HTML_TAGS, strip=True)
        
        return value.strip()
    
    @staticmethod
    def validate_email(email: str) -> str:
        """Validate and sanitize email address."""
        email = InputValidator.sanitize_string(email, max_length=254)
        
        # Basic email regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError("Invalid email format")
        
        return email.lower()
    
    @staticmethod
    def validate_url(url: str, allowed_schemes: List[str] = None) -> str:
        """Validate and sanitize URL."""
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']
        
        url = InputValidator.sanitize_string(url, max_length=2048)
        
        # Parse URL
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Check scheme
            if parsed.scheme not in allowed_schemes:
                raise ValueError(f"URL scheme must be one of: {allowed_schemes}")
            
            # Check for localhost/private IPs (SSRF protection)
            if parsed.hostname:
                if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
                    raise ValueError("Local URLs are not allowed")
                
                # Check for private IP ranges
                if re.match(r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)', parsed.hostname):
                    raise ValueError("Private IP addresses are not allowed")
            
            # Reconstruct URL to ensure it's properly formatted
            return urllib.parse.urlunparse(parsed)
            
        except Exception as e:
            raise ValueError(f"Invalid URL: {str(e)}")
    
    @staticmethod
    def validate_uuid(uuid_str: str) -> str:
        """Validate UUID format."""
        uuid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        if not re.match(uuid_pattern, uuid_str):
            raise ValueError("Invalid UUID format")
        return uuid_str.lower()
    
    @staticmethod
    def check_sql_injection(value: str) -> bool:
        """Check for potential SQL injection patterns."""
        value_upper = value.upper()
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_upper, re.IGNORECASE):
                logger.warning(f"Potential SQL injection detected: {pattern}")
                return True
        return False
    
    @staticmethod
    def check_xss(value: str) -> bool:
        """Check for potential XSS patterns."""
        for pattern in XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"Potential XSS detected: {pattern}")
                return True
        return False
    
    @staticmethod
    def check_path_traversal(value: str) -> bool:
        """Check for path traversal attempts."""
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value):
                logger.warning(f"Potential path traversal detected: {pattern}")
                return True
        return False
    
    @staticmethod
    def validate_json_payload(payload: Dict[str, Any], max_depth: int = 10) -> Dict[str, Any]:
        """Validate and sanitize JSON payload."""
        def _validate_recursive(obj: Any, depth: int = 0) -> Any:
            if depth > max_depth:
                raise ValueError("JSON payload exceeds maximum depth")
            
            if isinstance(obj, dict):
                if len(obj) > MAX_ARRAY_LENGTH:
                    raise ValueError(f"Dictionary exceeds maximum size of {MAX_ARRAY_LENGTH}")
                return {k: _validate_recursive(v, depth + 1) for k, v in obj.items()}
            
            elif isinstance(obj, list):
                if len(obj) > MAX_ARRAY_LENGTH:
                    raise ValueError(f"Array exceeds maximum length of {MAX_ARRAY_LENGTH}")
                return [_validate_recursive(item, depth + 1) for item in obj]
            
            elif isinstance(obj, str):
                # Check for malicious patterns
                if InputValidator.check_sql_injection(obj):
                    raise ValueError("Potential SQL injection detected")
                if InputValidator.check_xss(obj):
                    raise ValueError("Potential XSS detected")
                if InputValidator.check_path_traversal(obj):
                    raise ValueError("Potential path traversal detected")
                
                return InputValidator.sanitize_string(obj)
            
            elif isinstance(obj, (int, float, bool, type(None))):
                return obj
            
            else:
                raise ValueError(f"Unsupported type in JSON: {type(obj)}")
        
        return _validate_recursive(payload)

# Pydantic models with built-in validation
class SecureStringField(constr):
    """Secure string field with validation."""
    min_length = 1
    max_length = MAX_STRING_LENGTH
    strip_whitespace = True

class SecureInstruction(BaseModel):
    """Validated instruction model."""
    instruction: SecureStringField = Field(..., description="The instruction to analyze")
    session_id: constr(regex=r'^[0-9a-fA-F-]{36}$') = Field(..., description="Session UUID")
    client_id: Optional[SecureStringField] = None
    server_id: Optional[SecureStringField] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('instruction')
    def validate_instruction(cls, v):
        """Additional instruction validation."""
        if InputValidator.check_sql_injection(v):
            raise ValueError("Invalid instruction content")
        if InputValidator.check_xss(v):
            raise ValueError("Invalid instruction content")
        return v
    
    @validator('context')
    def validate_context(cls, v):
        """Validate context payload."""
        return InputValidator.validate_json_payload(v)

class SecureTokenRevocation(BaseModel):
    """Validated token revocation request."""
    token: SecureStringField = Field(..., description="Token to revoke")
    reason: SecureStringField = Field(..., description="Revocation reason")
    priority: constr(regex=r'^(low|medium|high|critical)$') = Field(default="medium")
    
    @validator('token')
    def validate_token(cls, v):
        """Validate token format."""
        # Basic token format validation
        if not re.match(r'^[\w-]+$', v):
            raise ValueError("Invalid token format")
        return v

class SecureAlert(BaseModel):
    """Validated alert creation request."""
    title: constr(min_length=1, max_length=200) = Field(..., description="Alert title")
    description: constr(min_length=1, max_length=5000) = Field(..., description="Alert description")
    severity: constr(regex=r'^(low|medium|high|critical)$') = Field(..., description="Alert severity")
    category: SecureStringField = Field(..., description="Alert category")
    source: SecureStringField = Field(..., description="Alert source")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('title', 'description', 'category', 'source')
    def validate_text_fields(cls, v):
        """Validate text fields for security."""
        if InputValidator.check_xss(v):
            raise ValueError("Invalid content detected")
        return InputValidator.sanitize_string(v)
    
    @validator('metadata')
    def validate_metadata(cls, v):
        """Validate metadata payload."""
        return InputValidator.validate_json_payload(v, max_depth=5)

class SecureVulnerabilityScan(BaseModel):
    """Validated vulnerability scan request."""
    server_id: SecureStringField = Field(..., description="Server ID to scan")
    scan_type: constr(regex=r'^(quick|full|custom)$') = Field(default="quick")
    target_url: Optional[str] = None
    include_tests: List[constr(regex=r'^[\w_]+$')] = Field(default_factory=list)
    
    @validator('target_url')
    def validate_target_url(cls, v):
        """Validate target URL."""
        if v:
            return InputValidator.validate_url(v)
        return v
    
    @validator('include_tests')
    def validate_test_list(cls, v):
        """Validate test list."""
        if len(v) > 20:
            raise ValueError("Too many tests specified")
        allowed_tests = [
            'connection_security', 'capability_audit', 'sandbox_testing',
            'authentication_check', 'authorization_check', 'token_security'
        ]
        for test in v:
            if test not in allowed_tests:
                raise ValueError(f"Invalid test: {test}")
        return v

# Request size limiter middleware
async def validate_request_size(request):
    """Validate request size to prevent DoS."""
    content_length = request.headers.get('content-length')
    if content_length:
        if int(content_length) > MAX_REQUEST_SIZE:
            raise ValueError(f"Request size exceeds maximum of {MAX_REQUEST_SIZE} bytes")

# Export validator instance
input_validator = InputValidator()