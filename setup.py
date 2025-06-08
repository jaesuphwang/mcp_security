# Copyright 2025 Jae Sup Hwang
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

# Filter out any lines that start with # or are empty
requirements = [req for req in requirements if req and not req.startswith("#")]

setup(
    name="mcp-security-guardian",
    version="1.0.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=requirements,
    author="Jae Sup Hwang",
    author_email="jaesuphwang@gmail.com",
    maintainer="Jae Sup Hwang",
    maintainer_email="jaesuphwang@gmail.com",
    description="MCP Security Guardian - A comprehensive security solution for the Model Context Protocol ecosystem",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    license="Apache 2.0",
    url="https://github.com/jaesuphwang/mcp_security",
    project_urls={
        "Bug Tracker": "https://github.com/jaesuphwang/mcp_security/issues",
        "Documentation": "https://github.com/jaesuphwang/mcp_security/wiki",
        "Source Code": "https://github.com/jaesuphwang/mcp_security",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "mcp-security-guardian=mcp_server:main",
            "mcp-security-basic=test_mcp_basic:main",
        ],
    },
    package_data={
        "detection_engine": ["data/*", "*.json", "*.yml"],
        "vulnerability_scanning": ["data/*", "*.json", "*.yml"],
        "revocation": ["data/*", "*.json", "*.yml"],
        "alerting": ["data/*", "*.json", "*.yml"],
        "core": ["*.json", "*.yml"],
    },
    include_package_data=True,
    keywords=[
        "mcp",
        "security",
        "threat-detection",
        "vulnerability-scanning", 
        "model-context-protocol",
        "ai-security",
        "cybersecurity",
        "token-management",
        "threat-intelligence",
    ],
) 