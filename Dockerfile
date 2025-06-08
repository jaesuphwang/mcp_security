FROM python:3.11-slim

WORKDIR /app

# Install only MCP SDK
RUN pip install --no-cache-dir mcp>=1.9.0

# Copy ultra-minimal server
COPY test_ultra_minimal.py /app/

# Run the ultra-minimal server
CMD ["python3", "test_ultra_minimal.py"] 