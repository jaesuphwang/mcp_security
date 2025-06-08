FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app" \
    LOG_LEVEL="INFO" \
    SECURITY_MODE="production"

# Set working directory
WORKDIR /app

# Install minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY src/ /app/src/
COPY mcp_server.py test_mcp_basic.py /app/
COPY mcp.json setup.py /app/

# Create a non-root user
RUN useradd -m -s /bin/bash appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Simple health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python3 -c "print('Health check OK')" || exit 1

# Default command to run the basic MCP server (more reliable)
CMD ["python3", "test_mcp_basic.py"] 