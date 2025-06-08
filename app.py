#!/usr/bin/env python3
"""
Simple HTTP server for Smithery deployment test
"""

import http.server
import socketserver
import threading
import time

PORT = 8080

class SimpleHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        
        response = """
        <html>
        <head><title>MCP Security Guardian Test</title></head>
        <body>
            <h1>🚀 MCP Security Guardian</h1>
            <p>✅ Container is running successfully!</p>
            <p>📦 Smithery deployment test</p>
            <p>⏰ Server started at: """ + str(time.ctime()) + """</p>
        </body>
        </html>
        """
        
        self.wfile.write(response.encode())
    
    def log_message(self, format, *args):
        # Custom logging
        print(f"[{time.ctime()}] {format % args}")

def start_server():
    """Start the HTTP server"""
    print(f"🚀 Starting simple HTTP server on port {PORT}")
    print(f"✅ Server ready at http://localhost:{PORT}")
    
    with socketserver.TCPServer(("", PORT), SimpleHandler) as httpd:
        print(f"📡 Serving HTTP on port {PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    try:
        print("🎯 MCP Security Guardian - Simple Test Server")
        print("📦 Smithery deployment verification")
        start_server()
    except KeyboardInterrupt:
        print("⏹️ Server stopped")
    except Exception as e:
        print(f"❌ Error: {e}")
        exit(1) 