#!/usr/bin/env python3
"""
Secure sandbox test runner for MCP server testing.
This runs inside the Docker container with restricted privileges.
"""
import sys
import json
import traceback
from typing import Dict, Any

def run_test(test_code: str) -> Dict[str, Any]:
    """
    Execute test code and return results.
    
    Args:
        test_code: Python code to execute
        
    Returns:
        Test results dictionary
    """
    # Create a restricted globals environment
    restricted_globals = {
        '__builtins__': {
            'print': print,
            'len': len,
            'str': str,
            'int': int,
            'float': float,
            'bool': bool,
            'dict': dict,
            'list': list,
            'tuple': tuple,
            'set': set,
            'range': range,
            'enumerate': enumerate,
            'zip': zip,
            'map': map,
            'filter': filter,
            'sum': sum,
            'min': min,
            'max': max,
            'any': any,
            'all': all,
            'sorted': sorted,
            'reversed': reversed,
            'isinstance': isinstance,
            'hasattr': hasattr,
            'getattr': getattr,
            'setattr': setattr,
            'Exception': Exception,
            'ValueError': ValueError,
            'TypeError': TypeError,
            'KeyError': KeyError,
            'IndexError': IndexError,
            'json': json,
        },
        'json': json,
    }
    
    # Import allowed modules
    try:
        import requests
        restricted_globals['requests'] = requests
    except ImportError:
        pass
    
    # Create local variables
    local_vars = {}
    
    try:
        # Execute the test code
        exec(test_code, restricted_globals, local_vars)
        
        # Extract results
        return {
            "success": True,
            "output": local_vars.get("result", {}),
            "error": None
        }
    except Exception as e:
        return {
            "success": False,
            "output": None,
            "error": {
                "type": type(e).__name__,
                "message": str(e),
                "traceback": traceback.format_exc()
            }
        }

def main():
    """Main entry point for sandbox runner."""
    # Read test code from stdin
    test_code = sys.stdin.read()
    
    # Run the test
    result = run_test(test_code)
    
    # Output results as JSON
    print(json.dumps(result))

if __name__ == "__main__":
    main()