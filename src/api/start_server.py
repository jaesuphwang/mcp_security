"""
Script to start the API server on port 8003.
"""
import uvicorn
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.api.main import app

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003, log_level="info") 