# Secure sandbox container for MCP testing
FROM python:3.11-slim

# Install security tools and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    strace \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create non-privileged user
RUN useradd -m -u 1000 -s /bin/false sandbox && \
    mkdir -p /app /sandbox && \
    chown -R sandbox:sandbox /app /sandbox

# Install Python security libraries
RUN pip install --no-cache-dir \
    requests==2.31.0 \
    aiohttp==3.9.1 \
    pydantic==2.5.0

# Copy sandbox test runner
COPY --chown=sandbox:sandbox sandbox_runner.py /app/

# Set security options
USER sandbox
WORKDIR /sandbox

# Disable Python bytecode writing
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Read-only root filesystem
# Additional security will be applied at runtime

ENTRYPOINT ["python", "/app/sandbox_runner.py"]