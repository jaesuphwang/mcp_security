#!/usr/bin/env python3
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
MCP Security Guardian - Enhanced Demo with Security Features

This enhanced demo showcases the new security features including:
- Input validation and sanitization
- JWT authentication with strong algorithms
- Password security with breach detection
- Rate limiting simulation
- Security logging with PII redaction
"""
import asyncio
import json
import uuid
import random
import logging
import hashlib
import base64
import secrets
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("mcp_guardian_enhanced_demo")

# --- Enhanced Security Patterns ---

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    r"('\s*or\s*'1'\s*=\s*'1)", r"(drop\s+table)", r"(delete\s+from)",
    r"(union\s+select)", r"(insert\s+into)", r"(update\s+.*\s+set)",
    r"(;--)", r"(/\*.*\*/)", r"(xp_)", r"(sp_)"
]

# XSS patterns
XSS_PATTERNS = [
    r"<script", r"</script>", r"javascript:", r"onerror\s*=",
    r"onload\s*=", r"<iframe", r"<embed", r"<object",
    r"alert\s*\(", r"prompt\s*\(", r"confirm\s*\("
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\", r"%2e%2e", r"\.\.\.\./", r"\.\.;"
]

# Password breach database (mock)
BREACHED_PASSWORD_HASHES = {
    "5e884898da28047151d0e56f8dc6292773603d0d": "password",
    "7c4a8d09ca3762af61e59520943dc26494f8941b": "123456",
    "f7c3bc1d808e04732adf679965ccc34ca7ae3441": "123456789",
    "b1b3773a05c0ed0176787a4f1574ff0075f7521e": "qwerty"
}

# --- Enhanced Mock Components ---

class EnhancedInputValidator:
    """Enhanced input validation with security features."""
    
    @staticmethod
    def check_sql_injection(value: str) -> bool:
        """Check for SQL injection patterns."""
        value_lower = value.lower()
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def check_xss(value: str) -> bool:
        """Check for XSS patterns."""
        value_lower = value.lower()
        for pattern in XSS_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def check_path_traversal(value: str) -> bool:
        """Check for path traversal patterns."""
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value):
                return True
        return False
    
    @staticmethod
    def sanitize_input(value: str) -> str:
        """Sanitize input by removing dangerous characters."""
        # Remove null bytes
        value = value.replace('\x00', '')
        # HTML escape
        value = value.replace('<', '&lt;').replace('>', '&gt;')
        # Limit length
        return value[:1000]


class SecureJWTManager:
    """Secure JWT implementation with strong algorithms."""
    
    def __init__(self):
        self.algorithm = "RS256"  # Force strong algorithm
        self.csrf_tokens = {}
        self.jwt_blacklist = set()
    
    def create_token(self, user_id: str, permissions: List[str]) -> Dict[str, Any]:
        """Create a secure JWT token."""
        jti = str(uuid.uuid4())  # JWT ID for tracking
        
        # In real implementation, this would use actual RS256 signing
        header = base64.urlsafe_b64encode(json.dumps({
            "alg": self.algorithm,
            "typ": "JWT"
        }).encode()).decode()
        
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": user_id,
            "permissions": permissions,
            "exp": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
            "iat": datetime.utcnow().isoformat(),
            "jti": jti
        }).encode()).decode()
        
        # Mock signature
        signature = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        
        token = f"{header}.{payload}.{signature}"
        
        return {
            "token": token,
            "jti": jti,
            "algorithm": self.algorithm,
            "expires_in": 3600
        }
    
    def generate_csrf_token(self, user_id: str) -> str:
        """Generate CSRF token."""
        token = secrets.token_urlsafe(32)
        self.csrf_tokens[user_id] = token
        return token
    
    def validate_csrf_token(self, user_id: str, token: str) -> bool:
        """Validate CSRF token."""
        return self.csrf_tokens.get(user_id) == token
    
    def revoke_token(self, jti: str):
        """Revoke a token by its JTI."""
        self.jwt_blacklist.add(jti)


class EnhancedPasswordManager:
    """Enhanced password security with breach detection."""
    
    def __init__(self):
        self.failed_attempts = {}
        self.lockout_threshold = 5
        self.password_history = {}
    
    def validate_password(self, password: str) -> Dict[str, Any]:
        """Validate password strength."""
        errors = []
        
        # Length check
        if len(password) < 12:
            errors.append("Password must be at least 12 characters")
        
        # Complexity checks
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain uppercase letters")
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain lowercase letters")
        if not re.search(r'[0-9]', password):
            errors.append("Password must contain numbers")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain special characters")
        
        # Check for common patterns
        common_patterns = ['password', '123456', 'qwerty', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            errors.append("Password contains common patterns")
        
        # Check breach database
        pwd_hash = hashlib.sha1(password.encode()).hexdigest()
        if pwd_hash in BREACHED_PASSWORD_HASHES:
            errors.append("Password found in breach database")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "score": max(0, 5 - len(errors))  # Simple scoring
        }
    
    def hash_password(self, password: str) -> str:
        """Hash password with Argon2 (simulated)."""
        # In real implementation, use argon2-cffi
        salt = secrets.token_bytes(16)
        return f"argon2${base64.b64encode(salt).decode()}${hashlib.sha256(password.encode() + salt).hexdigest()}"
    
    def check_account_lockout(self, user_id: str) -> bool:
        """Check if account is locked out."""
        attempts = self.failed_attempts.get(user_id, 0)
        return attempts >= self.lockout_threshold
    
    def record_failed_attempt(self, user_id: str):
        """Record a failed login attempt."""
        self.failed_attempts[user_id] = self.failed_attempts.get(user_id, 0) + 1


class RateLimiter:
    """Simple rate limiter simulation."""
    
    def __init__(self):
        self.requests = {}
        self.limits = {
            "analyze": {"requests": 100, "window": 60},  # 100 req/min
            "scan": {"requests": 10, "window": 600},     # 10 req/10min
            "revoke": {"requests": 5, "window": 60}      # 5 req/min
        }
    
    def check_rate_limit(self, client_ip: str, endpoint: str) -> Dict[str, Any]:
        """Check if request should be rate limited."""
        key = f"{client_ip}:{endpoint}"
        current_time = datetime.utcnow()
        
        if key not in self.requests:
            self.requests[key] = []
        
        # Remove old requests outside window
        limit = self.limits.get(endpoint, {"requests": 100, "window": 60})
        window_start = current_time - timedelta(seconds=limit["window"])
        self.requests[key] = [req_time for req_time in self.requests[key] if req_time > window_start]
        
        # Check if limit exceeded
        if len(self.requests[key]) >= limit["requests"]:
            return {
                "allowed": False,
                "retry_after": limit["window"],
                "limit": limit["requests"],
                "remaining": 0
            }
        
        # Add current request
        self.requests[key].append(current_time)
        
        return {
            "allowed": True,
            "limit": limit["requests"],
            "remaining": limit["requests"] - len(self.requests[key])
        }


class SecurityLogger:
    """Security-aware logger with PII redaction."""
    
    SENSITIVE_FIELDS = ['password', 'token', 'api_key', 'secret', 'ssn', 'credit_card']
    
    @staticmethod
    def redact_sensitive_data(data: Any) -> Any:
        """Recursively redact sensitive data."""
        if isinstance(data, dict):
            return {
                k: "[REDACTED]" if k.lower() in SecurityLogger.SENSITIVE_FIELDS else SecurityLogger.redact_sensitive_data(v)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [SecurityLogger.redact_sensitive_data(item) for item in data]
        elif isinstance(data, str):
            # Redact credit card numbers
            data = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[REDACTED-CC]', data)
            # Redact SSN
            data = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]', data)
            return data
        return data
    
    @staticmethod
    def log_security_event(event_type: str, details: Dict[str, Any]):
        """Log a security event with redacted sensitive data."""
        redacted_details = SecurityLogger.redact_sensitive_data(details)
        logger.info(f"SECURITY_EVENT [{event_type}]: {json.dumps(redacted_details, indent=2)}")


# --- Enhanced Demo Application ---

class EnhancedMCPGuardianDemo:
    """Enhanced demo showcasing security features."""
    
    def __init__(self):
        self.input_validator = EnhancedInputValidator()
        self.jwt_manager = SecureJWTManager()
        self.password_manager = EnhancedPasswordManager()
        self.rate_limiter = RateLimiter()
        self.security_logger = SecurityLogger()
    
    async def demo_input_validation(self):
        """Demonstrate input validation and sanitization."""
        print("\n=== Enhanced Input Validation Demo ===")
        
        test_inputs = [
            ("Hello, world!", "Safe input"),
            ("'; DROP TABLE users; --", "SQL injection attempt"),
            ("<script>alert('xss')</script>", "XSS attempt"),
            ("../../etc/passwd", "Path traversal attempt"),
            ("SELECT * FROM users WHERE id = 1", "Suspicious but not malicious")
        ]
        
        for input_text, description in test_inputs:
            print(f"\nTesting: {description}")
            print(f"Input: '{input_text}'")
            
            # Check for various attacks
            sql_injection = self.input_validator.check_sql_injection(input_text)
            xss = self.input_validator.check_xss(input_text)
            path_traversal = self.input_validator.check_path_traversal(input_text)
            
            if sql_injection:
                print("  ⚠️  SQL injection detected!")
            if xss:
                print("  ⚠️  XSS attempt detected!")
            if path_traversal:
                print("  ⚠️  Path traversal detected!")
            
            if not (sql_injection or xss or path_traversal):
                print("  ✅ Input appears safe")
            
            # Sanitize input
            sanitized = self.input_validator.sanitize_input(input_text)
            if sanitized != input_text:
                print(f"  Sanitized: '{sanitized}'")
    
    async def demo_jwt_security(self):
        """Demonstrate JWT security features."""
        print("\n=== JWT Security Demo ===")
        
        user_id = "demo_user_123"
        permissions = ["read", "write"]
        
        # Create secure token
        print(f"\nCreating token for user: {user_id}")
        token_info = self.jwt_manager.create_token(user_id, permissions)
        print(f"Algorithm: {token_info['algorithm']} (strong algorithm enforced)")
        print(f"JTI: {token_info['jti']} (for tracking/revocation)")
        print(f"Token: {token_info['token'][:50]}...")
        
        # Generate CSRF token
        csrf_token = self.jwt_manager.generate_csrf_token(user_id)
        print(f"\nCSRF Token generated: {csrf_token[:20]}...")
        
        # Validate CSRF
        is_valid = self.jwt_manager.validate_csrf_token(user_id, csrf_token)
        print(f"CSRF validation: {'✅ Valid' if is_valid else '❌ Invalid'}")
        
        # Demonstrate token revocation
        print(f"\nRevoking token with JTI: {token_info['jti']}")
        self.jwt_manager.revoke_token(token_info['jti'])
        print("Token added to blacklist")
    
    async def demo_password_security(self):
        """Demonstrate password security features."""
        print("\n=== Password Security Demo ===")
        
        test_passwords = [
            ("password123", "Common weak password"),
            ("P@ssw0rd", "Better but too short"),
            ("MySuper$ecure#Pass2024!", "Strong password"),
            ("123456", "Breached password")
        ]
        
        for password, description in test_passwords:
            print(f"\nTesting: {description}")
            print(f"Password: {'*' * len(password)}")
            
            # Validate password
            validation = self.password_manager.validate_password(password)
            
            if validation['valid']:
                print(f"  ✅ Password is valid (score: {validation['score']}/5)")
                # Hash the password
                hashed = self.password_manager.hash_password(password)
                print(f"  Hashed: {hashed[:50]}...")
            else:
                print(f"  ❌ Password validation failed:")
                for error in validation['errors']:
                    print(f"    - {error}")
        
        # Demonstrate account lockout
        print("\n--- Account Lockout Demo ---")
        test_user = "demo_user"
        
        for i in range(6):
            self.password_manager.record_failed_attempt(test_user)
            is_locked = self.password_manager.check_account_lockout(test_user)
            print(f"Failed attempt #{i+1}: Account {'🔒 LOCKED' if is_locked else '🔓 Active'}")
    
    async def demo_rate_limiting(self):
        """Demonstrate rate limiting."""
        print("\n=== Rate Limiting Demo ===")
        
        client_ip = "192.168.1.100"
        
        # Test analyze endpoint (high limit)
        print("\nTesting 'analyze' endpoint (limit: 100/min):")
        for i in range(5):
            result = self.rate_limiter.check_rate_limit(client_ip, "analyze")
            print(f"  Request {i+1}: {'✅ Allowed' if result['allowed'] else '❌ Blocked'} (remaining: {result['remaining']})")
        
        # Test revoke endpoint (low limit)
        print("\nTesting 'revoke' endpoint (limit: 5/min):")
        for i in range(7):
            result = self.rate_limiter.check_rate_limit(client_ip, "revoke")
            if result['allowed']:
                print(f"  Request {i+1}: ✅ Allowed (remaining: {result['remaining']})")
            else:
                print(f"  Request {i+1}: ❌ Rate limited! Retry after {result['retry_after']}s")
    
    async def demo_security_logging(self):
        """Demonstrate security logging with PII redaction."""
        print("\n=== Security Logging Demo ===")
        
        # Log various security events
        events = [
            ("LOGIN_ATTEMPT", {
                "user_id": "user123",
                "password": "secret123",  # Should be redacted
                "ip_address": "192.168.1.100",
                "success": False
            }),
            ("API_KEY_USAGE", {
                "api_key": "sk-1234567890abcdef",  # Should be redacted
                "endpoint": "/api/analyze",
                "user_id": "user456"
            }),
            ("SENSITIVE_DATA_ACCESS", {
                "user": "john.doe",
                "accessed_data": "User SSN: 123-45-6789",  # Should be redacted
                "credit_card": "4111 1111 1111 1111",  # Should be redacted
                "timestamp": datetime.utcnow().isoformat()
            })
        ]
        
        for event_type, details in events:
            print(f"\nLogging {event_type}:")
            print("Original data:", json.dumps(details, indent=2))
            self.security_logger.log_security_event(event_type, details)
    
    async def run_full_demo(self):
        """Run all security demonstrations."""
        print("\n" + "="*60)
        print("MCP SECURITY GUARDIAN - ENHANCED SECURITY DEMO")
        print("="*60)
        
        await self.demo_input_validation()
        await asyncio.sleep(1)
        
        await self.demo_jwt_security()
        await asyncio.sleep(1)
        
        await self.demo_password_security()
        await asyncio.sleep(1)
        
        await self.demo_rate_limiting()
        await asyncio.sleep(1)
        
        await self.demo_security_logging()
        
        print("\n" + "="*60)
        print("Demo completed! All security features demonstrated.")
        print("="*60)


async def main():
    """Main entry point."""
    demo = EnhancedMCPGuardianDemo()
    await demo.run_full_demo()


if __name__ == "__main__":
    asyncio.run(main())