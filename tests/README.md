# MCP Security Guardian Test Suite

This directory contains the comprehensive test suite for the MCP Security Guardian project.

## Running Tests

### Prerequisites
```bash
pip install pytest pytest-asyncio pytest-cov
```

### Run All Tests
```bash
# From project root
pytest tests/

# With coverage report
pytest tests/ --cov=src --cov-report=html
```

### Run Specific Test Categories

```bash
# API endpoint tests
pytest tests/test_api_endpoints.py

# Security component tests  
pytest tests/test_security_components.py

# Integration tests
pytest tests/test_integration.py

# Comprehensive security tests
pytest tests/test_comprehensive_security.py
```

## Test Categories

- **test_api_endpoints.py** - Tests for all REST API endpoints
- **test_security_components.py** - Unit tests for security modules
- **test_basic_functionality.py** - Basic functionality tests
- **test_integration.py** - Integration tests between components
- **test_comprehensive_security.py** - Full security feature tests
- **test_security_final.py** - Final security validation tests
- **test_security_features_mock.py** - Mock-based security tests
- **test_security_validation.py** - Input validation tests

## Writing New Tests

Follow the existing patterns and ensure all new features have corresponding tests.