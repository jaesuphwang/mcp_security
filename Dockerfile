FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt /app/

# Install dependencies
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt


# Final stage
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app" \
    LOG_LEVEL="INFO" \
    SECURITY_MODE="production"

# Create a non-root user
RUN useradd -m -s /bin/bash appuser

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy wheels from builder stage
COPY --from=builder /app/wheels /wheels
COPY --from=builder /app/requirements.txt .

# Install dependencies from wheels
RUN pip install --no-cache /wheels/*

# Copy application files
COPY --chown=appuser:appuser src/ /app/src/
COPY --chown=appuser:appuser mcp_server.py test_mcp_basic.py /app/
COPY --chown=appuser:appuser requirements.txt setup.py README.md LICENSE /app/
COPY --chown=appuser:appuser mcp.json /app/

# Switch to non-root user
USER appuser

# Expose port (for MCP server)
EXPOSE 8000

# Health check for basic server verification
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "import sys; sys.path.insert(0, '/app'); exec(open('/app/test_mcp_basic.py').read().split('asyncio.run(main())')[0]); print('Server OK')" || exit 1

# Default command to run the MCP server
CMD ["python3", "mcp_server.py"] 