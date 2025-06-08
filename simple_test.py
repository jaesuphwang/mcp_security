#!/usr/bin/env python3
"""
Absolute minimal test script for Smithery deployment
Tests basic Python container functionality without any dependencies.
"""

import time
import sys

print("🚀 Starting absolute minimal test...")
print("✅ Python is working")
print("📦 Container is running")
print("⏰ Starting keep-alive loop...")

# Simple keep-alive loop
try:
    counter = 0
    while True:
        counter += 1
        print(f"💗 Heartbeat {counter} - Container is alive")
        time.sleep(30)
        
        # Exit after 10 minutes to prevent infinite loops
        if counter > 20:
            print("⏰ Test complete - Container worked successfully!")
            break
            
except KeyboardInterrupt:
    print("⏹️ Test stopped by user")
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)

print("✅ Test completed successfully")
sys.exit(0) 