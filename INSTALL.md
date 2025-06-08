# Installation Guide - MCP Security Guardian

Quick installation guide for getting MCP Security Guardian up and running.

## Prerequisites

- Python 3.10 or higher
- Git
- Virtual environment support (recommended)

## Quick Install

### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/jaesuphwang/mcp_security.git
cd mcp_security

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Test Installation

```bash
# Test basic functionality
python test_mcp_basic.py

# Test full server (if no errors above)
python mcp_server.py
```

If both commands run without errors and show "MCP Security Guardian initialized successfully", you're ready to go!

## Claude Desktop Integration

### 1. Find Your Configuration File

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Linux:**
```
~/.config/Claude/claude_desktop_config.json
```

### 2. Add MCP Server Configuration

Edit the configuration file and add:

```json
{
  "mcpServers": {
    "mcp-security-guardian": {
      "command": "python",
      "args": ["/absolute/path/to/your/mcp_security/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/your/mcp_security"
      }
    }
  }
}
```

**Important:** Replace `/absolute/path/to/your/mcp_security` with the actual full path to your project directory.

### 3. Restart Claude Desktop

After saving the configuration, restart Claude Desktop to load the MCP server.

## Verification

In Claude Desktop, you should now be able to use the following tools:

- `analyze_instruction` - Analyze text for security threats
- `scan_connection` - Scan server connections for vulnerabilities  
- `revoke_token` - Revoke authentication tokens
- `audit_capabilities` - Audit server capabilities
- `distribute_alert` - Send security alerts

## Troubleshooting

### Common Issues

**1. Module not found errors:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

**2. Path issues in Claude Desktop:**
```bash
# Get absolute path
pwd
# Use this full path in claude_desktop_config.json
```

**3. Permission issues:**
```bash
# Make sure script is executable
chmod +x mcp_server.py test_mcp_basic.py
```

**4. Python version issues:**
```bash
# Check Python version
python --version

# Should be 3.10 or higher
# If not, install a newer Python version
```

## Alternative Installation Methods

### Using pip (Development Install)

```bash
# Install in development mode
pip install -e .

# Now you can run from anywhere
mcp-security-guardian
mcp-security-basic
```

### Using setup.py

```bash
# Install system-wide
python setup.py install

# Or development install
python setup.py develop
```

## Next Steps

Once installed, check out the main [README.md](README.md) for:

- Available tools and how to use them
- Security features overview
- Development setup
- Contributing guidelines

## Support

If you encounter issues:

1. Check the [troubleshooting section](README.md#troubleshooting) in the main README
2. Look for similar issues in [GitHub Issues](https://github.com/jaesuphwang/mcp_security/issues)
3. Create a new issue with details about your setup and the error

## Quick Test Commands

```bash
# Basic test - should show "Server initialized successfully"
python test_mcp_basic.py

# Full test - should show all security components loaded
python mcp_server.py

# Check dependencies
pip check

# Verify Python path
python -c "import sys; print(sys.path)"
```

That's it! You should now have MCP Security Guardian running and integrated with Claude Desktop. 