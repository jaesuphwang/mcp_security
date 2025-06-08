#!/usr/bin/env python3
"""
Comprehensive tests for security components.
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from datetime import datetime, timedelta
import uuid
from typing import Dict, Any

# Import security components
from core.auth.jwt import JWTManager
from core.auth.password import PasswordManager
from vulnerability_scanning.connection_security import ConnectionSecurityAnalyzer
from vulnerability_scanning.capability_auditor import CapabilityAuditor
from vulnerability_scanning.sandbox_testing import SandboxTestingSystem
from revocation.token_revocation import TokenRevocationService
from revocation.connection_termination import ConnectionTerminationService
from utils.rate_limiting import RateLimiter

class SecurityComponentTester:
    def __init__(self):
        self.test_results = []
        self.jwt_manager = JWTManager()
        self.password_manager = PasswordManager()
        self.rate_limiter = RateLimiter()

    def record_result(self, test_name: str, passed: bool, details: str):
        self.test_results.append({
            "test": test_name,
            "passed": passed,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        })
        print(f"{'✅' if passed else '❌'} {test_name}: {details}")

    async def test_jwt_authentication(self):
        """Test JWT token creation and validation."""
        print("\n=== Testing JWT Authentication ===")
        
        # Test access token creation
        user_data = {
            "sub": "user123",
            "organization_id": "org456",
            "roles": ["user", "admin"]
        }
        
        try:
            access_token = self.jwt_manager.create_access_token(user_data)
            self.record_result(
                "JWT Access Token Creation",
                bool(access_token),
                f"Token created: {access_token[:20]}..."
            )
            
            # Verify token
            payload = self.jwt_manager.verify_token(access_token)
            passed = payload is not None and payload.get("sub") == "user123"
            self.record_result(
                "JWT Token Verification",
                passed,
                f"Payload verified: {bool(payload)}"
            )
            
            # Test expired token
            expired_data = user_data.copy()
            expired_token = self.jwt_manager.create_access_token(
                expired_data,
                expires_delta=timedelta(seconds=-1)
            )
            expired_payload = self.jwt_manager.verify_token(expired_token)
            self.record_result(
                "JWT Expired Token Rejection",
                expired_payload is None,
                "Expired token properly rejected"
            )
            
        except Exception as e:
            self.record_result("JWT Authentication", False, f"Error: {str(e)}")

    async def test_password_security(self):
        """Test password hashing and verification."""
        print("\n=== Testing Password Security ===")
        
        test_passwords = [
            ("weak_password", "weak_password", True),
            ("strong_P@ssw0rd!", "strong_P@ssw0rd!", True),
            ("correct_password", "wrong_password", False)
        ]
        
        for password, verify_password, should_match in test_passwords:
            try:
                # Hash password
                hashed = self.password_manager.hash_password(password)
                self.record_result(
                    f"Password Hashing - {password[:4]}...",
                    bool(hashed) and hashed != password,
                    "Password hashed successfully"
                )
                
                # Verify password
                is_valid = self.password_manager.verify_password(verify_password, hashed)
                passed = is_valid == should_match
                self.record_result(
                    f"Password Verification - {password[:4]}... vs {verify_password[:4]}...",
                    passed,
                    f"Expected: {should_match}, Got: {is_valid}"
                )
                
            except Exception as e:
                self.record_result("Password Security", False, f"Error: {str(e)}")

    async def test_rate_limiting(self):
        """Test rate limiting functionality."""
        print("\n=== Testing Rate Limiting ===")
        
        key = "test_user_123"
        max_requests = 5
        window_seconds = 60
        
        # Configure rate limiter
        self.rate_limiter.max_requests = max_requests
        self.rate_limiter.window_seconds = window_seconds
        
        # Test within limits
        for i in range(max_requests):
            is_allowed, info = await self.rate_limiter.check_rate_limit(key)
            if i < max_requests:
                self.record_result(
                    f"Rate Limit Check {i+1}/{max_requests}",
                    is_allowed,
                    f"Request allowed, remaining: {info.get('remaining', 0)}"
                )
        
        # Test exceeding limit
        is_allowed, info = await self.rate_limiter.check_rate_limit(key)
        self.record_result(
            "Rate Limit Exceeded",
            not is_allowed,
            f"Request blocked, retry after: {info.get('retry_after', 0)}s"
        )

    async def test_connection_security_analyzer(self):
        """Test connection security analysis."""
        print("\n=== Testing Connection Security Analyzer ===")
        
        analyzer = ConnectionSecurityAnalyzer()
        
        # Test HTTPS connection
        https_result = await analyzer.analyze_connection("https://example.com")
        self.record_result(
            "HTTPS Connection Analysis",
            https_result.scan_completed,
            f"Risk score: {https_result.risk_score}, Issues: {len(https_result.issues)}"
        )
        
        # Test HTTP connection (should flag as insecure)
        http_result = await analyzer.analyze_connection("http://example.com")
        has_tls_issue = any("TLS" in issue.title for issue in http_result.issues)
        self.record_result(
            "HTTP Connection Security Issue Detection",
            has_tls_issue,
            f"TLS issue detected: {has_tls_issue}"
        )

    async def test_capability_auditor(self):
        """Test capability auditing."""
        print("\n=== Testing Capability Auditor ===")
        
        auditor = CapabilityAuditor()
        
        # Test high-risk capability combination
        high_risk_caps = {
            "file_access": True,
            "network_access": True,
            "code_execution": True,
            "system_control": True
        }
        
        result = await auditor.audit_capabilities("test-server", high_risk_caps)
        self.record_result(
            "High-Risk Capability Detection",
            result.risk_score > 0.7,
            f"Risk score: {result.risk_score}, Issues: {len(result.issues)}"
        )
        
        # Test low-risk capabilities
        low_risk_caps = {
            "read_only": True,
            "data_processing": True
        }
        
        result = await auditor.audit_capabilities("test-server", low_risk_caps)
        self.record_result(
            "Low-Risk Capability Assessment",
            result.risk_score < 0.3,
            f"Risk score: {result.risk_score}"
        )

    async def test_sandbox_testing(self):
        """Test sandbox testing system."""
        print("\n=== Testing Sandbox Testing System ===")
        
        sandbox = SandboxTestingSystem()
        
        # Test malicious code execution detection
        result = await sandbox.test_server("test-server", "http://test.com")
        
        # Check if tests were executed
        self.record_result(
            "Sandbox Test Execution",
            result.tests_completed > 0,
            f"Tests completed: {result.tests_completed}/{result.total_tests}"
        )
        
        # Check if vulnerabilities were detected
        has_vulns = len(result.vulnerabilities) > 0
        self.record_result(
            "Vulnerability Detection",
            has_vulns,
            f"Vulnerabilities found: {len(result.vulnerabilities)}"
        )

    async def test_token_revocation(self):
        """Test token revocation service."""
        print("\n=== Testing Token Revocation Service ===")
        
        service = TokenRevocationService()
        
        # Test token revocation
        token = "test-token-" + str(uuid.uuid4())
        revocation_id = await service.revoke_token(
            token=token,
            reason="Test revocation",
            revoked_by="test_user"
        )
        
        self.record_result(
            "Token Revocation",
            bool(revocation_id),
            f"Revocation ID: {revocation_id}"
        )
        
        # Test blacklist check
        is_revoked = await service.is_token_revoked(token)
        self.record_result(
            "Token Blacklist Check",
            is_revoked,
            f"Token properly blacklisted: {is_revoked}"
        )
        
        # Test bulk revocation
        tokens = [f"bulk-token-{i}" for i in range(5)]
        bulk_result = await service.bulk_revoke_tokens(
            tokens=tokens,
            server_id="test-server",
            reason="Bulk test revocation"
        )
        
        self.record_result(
            "Bulk Token Revocation",
            bulk_result["revoked_count"] == len(tokens),
            f"Revoked {bulk_result['revoked_count']}/{len(tokens)} tokens"
        )

    async def test_connection_termination(self):
        """Test connection termination service."""
        print("\n=== Testing Connection Termination Service ===")
        
        service = ConnectionTerminationService()
        
        # Test connection termination
        result = await service.terminate_connection(
            client_id="test-client",
            server_id="test-server",
            connection_id="test-conn",
            reason="Security test",
            method="forceful"
        )
        
        self.record_result(
            "Connection Termination",
            result.success,
            f"Method: {result.method}, Duration: {result.termination_duration}ms"
        )
        
        # Test graceful termination
        graceful_result = await service.terminate_connection(
            client_id="test-client-2",
            server_id="test-server",
            connection_id="test-conn-2",
            reason="Graceful test",
            method="graceful"
        )
        
        self.record_result(
            "Graceful Connection Termination",
            graceful_result.success,
            f"Notifications sent: {graceful_result.notification_sent}"
        )

    def print_summary(self):
        """Print test summary."""
        print("\n" + "="*50)
        print("SECURITY COMPONENT TEST SUMMARY")
        print("="*50)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result["passed"])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests*100):.1f}%")
        
        if failed_tests > 0:
            print("\nFailed Tests:")
            for result in self.test_results:
                if not result["passed"]:
                    print(f"  - {result['test']}: {result['details']}")

async def main():
    """Run all security component tests."""
    print("Starting MCP Security Guardian Component Tests")
    print("="*50)
    
    tester = SecurityComponentTester()
    
    # Run all tests
    await tester.test_jwt_authentication()
    await tester.test_password_security()
    await tester.test_rate_limiting()
    await tester.test_connection_security_analyzer()
    await tester.test_capability_auditor()
    await tester.test_sandbox_testing()
    await tester.test_token_revocation()
    await tester.test_connection_termination()
    
    # Print summary
    tester.print_summary()

if __name__ == "__main__":
    asyncio.run(main())