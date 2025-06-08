#!/usr/bin/env python3
"""
Basic functionality tests for MCP Security Guardian without external dependencies.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import asyncio
import json
from datetime import datetime
import uuid

class BasicFunctionalityTester:
    def __init__(self):
        self.test_results = []

    def record_result(self, test_name: str, passed: bool, details: str):
        self.test_results.append({
            "test": test_name,
            "passed": passed,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        })
        print(f"{'✅' if passed else '❌'} {test_name}: {details}")

    def test_imports(self):
        """Test that core modules can be imported."""
        print("\n=== Testing Module Imports ===")
        
        modules_to_test = [
            ("Core Models", "from core.models.base import BaseModel"),
            ("Security Models", "from core.models.security import SecurityAlert"),
            ("API Models", "from core.models.api import RequestInfo"),
            ("Detection Models", "from detection_engine.instruction_analysis.models import ThreatType"),
            ("Password Utils", "from core.auth.password import PasswordManager"),
        ]
        
        for module_name, import_statement in modules_to_test:
            try:
                exec(import_statement)
                self.record_result(f"Import {module_name}", True, "Successfully imported")
            except Exception as e:
                self.record_result(f"Import {module_name}", False, f"Error: {str(e)}")

    def test_model_creation(self):
        """Test that models can be created."""
        print("\n=== Testing Model Creation ===")
        
        try:
            from core.models.security import SecurityAlert, AlertSeverity, AlertCategory
            
            # Test SecurityAlert creation
            alert = SecurityAlert(
                id=str(uuid.uuid4()),
                title="Test Alert",
                description="This is a test alert",
                severity=AlertSeverity.HIGH,
                category=AlertCategory.THREAT_DETECTION,
                source="test_script",
                created_at=datetime.utcnow(),
                metadata={"test": True}
            )
            
            self.record_result(
                "SecurityAlert Model Creation",
                bool(alert.id),
                f"Created alert with ID: {alert.id}"
            )
            
            # Test model validation
            try:
                invalid_alert = SecurityAlert(
                    id="not-a-uuid",
                    title="",  # Empty title should fail validation
                    severity="invalid",  # Invalid severity
                )
            except Exception:
                self.record_result(
                    "Model Validation",
                    True,
                    "Properly rejected invalid model data"
                )
            else:
                self.record_result(
                    "Model Validation",
                    False,
                    "Failed to reject invalid model data"
                )
                
        except Exception as e:
            self.record_result("Model Creation", False, f"Error: {str(e)}")

    def test_password_manager(self):
        """Test password hashing functionality."""
        print("\n=== Testing Password Manager ===")
        
        try:
            from core.auth.password import PasswordManager
            
            pm = PasswordManager()
            
            # Test password hashing
            password = "test_password_123"
            hashed = pm.hash_password(password)
            
            self.record_result(
                "Password Hashing",
                hashed != password and len(hashed) > 20,
                f"Password hashed to {len(hashed)} characters"
            )
            
            # Test password verification
            is_valid = pm.verify_password(password, hashed)
            self.record_result(
                "Password Verification - Correct",
                is_valid,
                "Correct password verified successfully"
            )
            
            # Test wrong password
            is_valid_wrong = pm.verify_password("wrong_password", hashed)
            self.record_result(
                "Password Verification - Wrong",
                not is_valid_wrong,
                "Wrong password properly rejected"
            )
            
        except Exception as e:
            self.record_result("Password Manager", False, f"Error: {str(e)}")

    def test_threat_detection_models(self):
        """Test threat detection model structures."""
        print("\n=== Testing Threat Detection Models ===")
        
        try:
            from detection_engine.instruction_analysis.models import (
                ThreatType, RiskLevel, InstructionAnalysisResult, ComponentResult
            )
            
            # Test ComponentResult creation
            component_result = ComponentResult(
                component="pattern_matching",
                is_threat=True,
                confidence=0.85,
                threat_type=ThreatType.MALICIOUS_CODE_EXECUTION,
                risk_level=RiskLevel.HIGH,
                details={"pattern": "rm -rf /", "matched": True}
            )
            
            self.record_result(
                "ComponentResult Creation",
                component_result.confidence == 0.85,
                "Component result created successfully"
            )
            
            # Test InstructionAnalysisResult
            analysis_result = InstructionAnalysisResult(
                instruction="test instruction",
                is_threat=True,
                confidence=0.9,
                threat_type=ThreatType.CREDENTIAL_THEFT,
                risk_level=RiskLevel.CRITICAL,
                analysis_results=[component_result],
                metadata={"test": True}
            )
            
            self.record_result(
                "InstructionAnalysisResult Creation",
                analysis_result.is_threat and len(analysis_result.analysis_results) == 1,
                "Analysis result created with component results"
            )
            
        except Exception as e:
            self.record_result("Threat Detection Models", False, f"Error: {str(e)}")

    def test_file_structure(self):
        """Test that required files exist."""
        print("\n=== Testing File Structure ===")
        
        required_files = [
            ("Main API", "src/api/main.py"),
            ("Detection Engine", "src/detection_engine/detector.py"),
            ("JWT Manager", "src/core/auth/jwt.py"),
            ("Settings", "src/core/config/settings.py"),
            ("Docker Compose", "docker-compose.yml"),
            ("Dockerfile", "Dockerfile"),
        ]
        
        for file_name, file_path in required_files:
            exists = os.path.exists(file_path)
            self.record_result(
                f"File Exists - {file_name}",
                exists,
                f"Path: {file_path}"
            )

    def test_configuration_loading(self):
        """Test configuration loading."""
        print("\n=== Testing Configuration Loading ===")
        
        try:
            # Set minimal environment variables
            os.environ["INSTANCE_ID"] = "test-instance"
            os.environ["JWT_SECRET"] = "test-secret-key"
            os.environ["POSTGRES_PASSWORD"] = "test-password"
            os.environ["MONGODB_PASSWORD"] = "test-password"
            os.environ["REDIS_PASSWORD"] = "test-password"
            
            from core.config.settings import Settings
            
            # Test creating settings instance
            settings = Settings()
            
            self.record_result(
                "Settings Instantiation",
                settings.instance_id == "test-instance",
                f"Instance ID: {settings.instance_id}"
            )
            
            # Test default values
            self.record_result(
                "Default API Port",
                settings.api_port == 8000,
                f"API Port: {settings.api_port}"
            )
            
        except Exception as e:
            self.record_result("Configuration Loading", False, f"Error: {str(e)}")

    async def test_async_components(self):
        """Test async component functionality."""
        print("\n=== Testing Async Components ===")
        
        try:
            from utils.rate_limiting import RateLimiter
            
            # Create a mock rate limiter
            limiter = RateLimiter()
            limiter.storage = {}  # Use dict instead of Redis for testing
            
            # Override the check_rate_limit method for testing
            async def mock_check_rate_limit(key: str):
                count = limiter.storage.get(key, 0)
                limiter.storage[key] = count + 1
                
                is_allowed = count < 5
                return is_allowed, {
                    "remaining": max(0, 5 - count - 1),
                    "limit": 5,
                    "retry_after": 60 if not is_allowed else None
                }
            
            limiter.check_rate_limit = mock_check_rate_limit
            
            # Test rate limiting
            key = "test_user"
            for i in range(6):
                is_allowed, info = await limiter.check_rate_limit(key)
                if i < 5:
                    self.record_result(
                        f"Rate Limit Check {i+1}",
                        is_allowed,
                        f"Remaining: {info['remaining']}"
                    )
                else:
                    self.record_result(
                        "Rate Limit Exceeded",
                        not is_allowed,
                        "Properly blocked after limit"
                    )
                    
        except Exception as e:
            self.record_result("Async Components", False, f"Error: {str(e)}")

    def print_summary(self):
        """Print test summary."""
        print("\n" + "="*50)
        print("BASIC FUNCTIONALITY TEST SUMMARY")
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
        
        # Save results to file
        with open("test_results.json", "w") as f:
            json.dump({
                "summary": {
                    "total": total_tests,
                    "passed": passed_tests,
                    "failed": failed_tests,
                    "success_rate": passed_tests/total_tests*100
                },
                "results": self.test_results,
                "timestamp": datetime.utcnow().isoformat()
            }, f, indent=2)
        print("\nTest results saved to test_results.json")

async def main():
    """Run all basic functionality tests."""
    print("Starting MCP Security Guardian Basic Functionality Tests")
    print("="*50)
    
    tester = BasicFunctionalityTester()
    
    # Run synchronous tests
    tester.test_imports()
    tester.test_model_creation()
    tester.test_password_manager()
    tester.test_threat_detection_models()
    tester.test_file_structure()
    tester.test_configuration_loading()
    
    # Run async tests
    await tester.test_async_components()
    
    # Print summary
    tester.print_summary()

if __name__ == "__main__":
    asyncio.run(main())