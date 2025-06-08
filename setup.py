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

setup(
    name="MCP_SECURITY",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=requirements,
    author="Jae Sup Hwang",
    author_email="jaesuphwang@gmail.com",
    maintainer="Jae Sup Hwang",
    maintainer_email="jaesuphwang@gmail.com",
    description="MCP Security Guardian Tool - A comprehensive security solution for the Model Context Protocol ecosystem",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    license="Apache 2.0",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "mcp-security=core.cli:main",
            "mcp-security-ws=api.websocket_server:run_server",
            "mcp-security-simple-ws=api.simple_ws_server:main",
        ],
    },
    package_data={
        "detection_engine": ["data/*"],
        "vulnerability_scanning": ["data/*"],
        "revocation": ["data/*"],
        "alerting": ["data/*"],
    },
) 