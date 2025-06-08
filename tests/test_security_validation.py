#!/usr/bin/env python3
"""
Test script to verify the secure input validation for security API routes.
"""
import asyncio
from pydantic import ValidationError
from src.core.security.input_validation import (
    SecureInstruction,
    SecureVulnerabilityScan,
    SecureTokenRevocation,
    input_validator
)

def test_secure_instruction():
    """Test SecureInstruction validation."""
    print("\n=== Testing SecureInstruction ===")
    
    # Valid instruction
    try:
        valid_instruction = SecureInstruction(
            instruction="Check the server status",
            session_id="550e8400-e29b-41d4-a716-446655440000",
            context={"user": "test", "action": "status_check"}
        )
        print("✓ Valid instruction passed")
    except ValidationError as e:
        print(f"✗ Valid instruction failed: {e}")
    
    # Invalid UUID
    try:
        invalid_uuid = SecureInstruction(
            instruction="Check status",
            session_id="invalid-uuid",
            context={}
        )
        print("✗ Invalid UUID should have failed")
    except ValidationError:
        print("✓ Invalid UUID correctly rejected")
    
    # SQL injection attempt
    try:
        sql_injection = SecureInstruction(
            instruction="'; DROP TABLE users; --",
            session_id="550e8400-e29b-41d4-a716-446655440000",
            context={}
        )
        print("✗ SQL injection should have failed")
    except ValidationError:
        print("✓ SQL injection correctly rejected")
    
    # XSS attempt
    try:
        xss_attempt = SecureInstruction(
            instruction="<script>alert('xss')</script>",
            session_id="550e8400-e29b-41d4-a716-446655440000",
            context={}
        )
        print("✗ XSS attempt should have failed")
    except ValidationError:
        print("✓ XSS attempt correctly rejected")

def test_secure_vulnerability_scan():
    """Test SecureVulnerabilityScan validation."""
    print("\n=== Testing SecureVulnerabilityScan ===")
    
    # Valid scan request
    try:
        valid_scan = SecureVulnerabilityScan(
            server_id="server-123",
            scan_type="quick",
            target_url="https://example.com",
            include_tests=["connection_security", "capability_audit"]
        )
        print("✓ Valid scan request passed")
    except ValidationError as e:
        print(f"✗ Valid scan failed: {e}")
    
    # Invalid scan type
    try:
        invalid_type = SecureVulnerabilityScan(
            server_id="server-123",
            scan_type="invalid-type"
        )
        print("✗ Invalid scan type should have failed")
    except ValidationError:
        print("✓ Invalid scan type correctly rejected")
    
    # Invalid URL
    try:
        invalid_url = SecureVulnerabilityScan(
            server_id="server-123",
            scan_type="quick",
            target_url="http://localhost:8080"  # Localhost not allowed
        )
        print("✗ Localhost URL should have failed")
    except ValidationError:
        print("✓ Localhost URL correctly rejected")
    
    # Invalid test
    try:
        invalid_test = SecureVulnerabilityScan(
            server_id="server-123",
            scan_type="quick",
            include_tests=["invalid_test", "connection_security"]
        )
        print("✗ Invalid test should have failed")
    except ValidationError:
        print("✓ Invalid test correctly rejected")

def test_secure_token_revocation():
    """Test SecureTokenRevocation validation."""
    print("\n=== Testing SecureTokenRevocation ===")
    
    # Valid revocation
    try:
        valid_revocation = SecureTokenRevocation(
            token="abc123-def456-ghi789",
            reason="Security breach detected",
            priority="high"
        )
        print("✓ Valid token revocation passed")
    except ValidationError as e:
        print(f"✗ Valid revocation failed: {e}")
    
    # Invalid token format
    try:
        invalid_token = SecureTokenRevocation(
            token="token with spaces!@#",
            reason="Test",
            priority="medium"
        )
        print("✗ Invalid token format should have failed")
    except ValidationError:
        print("✓ Invalid token format correctly rejected")
    
    # Invalid priority
    try:
        invalid_priority = SecureTokenRevocation(
            token="abc123",
            reason="Test",
            priority="urgent"  # Should be low/medium/high/critical
        )
        print("✗ Invalid priority should have failed")
    except ValidationError:
        print("✓ Invalid priority correctly rejected")

def test_input_validator():
    """Test InputValidator utility functions."""
    print("\n=== Testing InputValidator ===")
    
    # Test email validation
    try:
        valid_email = input_validator.validate_email("user@example.com")
        print(f"✓ Valid email: {valid_email}")
    except ValueError:
        print("✗ Valid email failed")
    
    try:
        invalid_email = input_validator.validate_email("not-an-email")
        print("✗ Invalid email should have failed")
    except ValueError:
        print("✓ Invalid email correctly rejected")
    
    # Test URL validation
    try:
        valid_url = input_validator.validate_url("https://example.com/api/test")
        print(f"✓ Valid URL: {valid_url}")
    except ValueError:
        print("✗ Valid URL failed")
    
    try:
        private_ip = input_validator.validate_url("http://192.168.1.1/admin")
        print("✗ Private IP should have failed")
    except ValueError:
        print("✓ Private IP correctly rejected")
    
    # Test UUID validation
    try:
        valid_uuid = input_validator.validate_uuid("550e8400-e29b-41d4-a716-446655440000")
        print(f"✓ Valid UUID: {valid_uuid}")
    except ValueError:
        print("✗ Valid UUID failed")
    
    # Test SQL injection detection
    sql_test = "SELECT * FROM users WHERE id = 1"
    if input_validator.check_sql_injection(sql_test):
        print("✓ SQL injection correctly detected")
    else:
        print("✗ SQL injection not detected")
    
    # Test XSS detection
    xss_test = "<img src=x onerror=alert(1)>"
    if input_validator.check_xss(xss_test):
        print("✓ XSS correctly detected")
    else:
        print("✗ XSS not detected")
    
    # Test path traversal detection
    path_test = "../../etc/passwd"
    if input_validator.check_path_traversal(path_test):
        print("✓ Path traversal correctly detected")
    else:
        print("✗ Path traversal not detected")

def main():
    """Run all tests."""
    print("Testing MCP Security Guardian Input Validation")
    print("=" * 50)
    
    test_secure_instruction()
    test_secure_vulnerability_scan()
    test_secure_token_revocation()
    test_input_validator()
    
    print("\n" + "=" * 50)
    print("Testing complete!")

if __name__ == "__main__":
    main()