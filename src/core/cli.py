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

"""
Command Line Interface for MCP Security Guardian Tool.
"""
import os
import sys
import typer
import uvicorn
from typing import Optional

from core.config.settings import settings
from core.utils.logging import logger, get_logger

# Create CLI app
app = typer.Typer(
    name="mcp-security",
    help="MCP Security Guardian Tool - A comprehensive security solution for MCP implementations",
    add_completion=False,
)


@app.command("start")
def start_all(
    host: str = typer.Option(settings.API_HOST, "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(settings.API_PORT, "--port", "-p", help="Port to bind to"),
    workers: int = typer.Option(1, "--workers", "-w", help="Number of worker processes"),
    log_level: str = typer.Option(settings.LOG_LEVEL.lower(), "--log-level", "-l", help="Log level"),
):
    """
    Start all MCP Security Guardian Tool services.
    """
    logger.info("Starting MCP Security Guardian Tool...")
    # This would typically start all services, but for simplicity we'll just
    # start the API server here.
    start_api(host, port, workers, log_level)


@app.command("api")
def start_api(
    host: str = typer.Option(settings.API_HOST, "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(settings.API_PORT, "--port", "-p", help="Port to bind to"),
    workers: int = typer.Option(1, "--workers", "-w", help="Number of worker processes"),
    log_level: str = typer.Option(settings.LOG_LEVEL.lower(), "--log-level", "-l", help="Log level"),
):
    """
    Start the API server.
    """
    logger.info(f"Starting API server on {host}:{port}...")
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        workers=workers,
        log_level=log_level,
        reload=settings.DEBUG,
    )


@app.command("admin")
def start_admin(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(3000, "--port", "-p", help="Port to bind to"),
):
    """
    Start the Admin UI server.
    """
    logger.info(f"Starting Admin UI server on {host}:{port}...")
    # This would typically start the Admin UI server, but for now we'll just log
    logger.info("Admin UI server not implemented yet.")


@app.command("db")
def db_commands(
    command: str = typer.Argument(..., help="Database command (init, migrate, reset)"),
):
    """
    Database management commands.
    """
    if command == "init":
        from core.database.connections import Base, engine
        logger.info("Initializing database...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully!")
    elif command == "migrate":
        logger.info("Running database migrations...")
        # This would typically run Alembic migrations
        logger.info("Database migrations not implemented yet.")
    elif command == "reset":
        from core.database.connections import Base, engine
        logger.info("Resetting database...")
        # Warning: this will delete all data!
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        logger.info("Database reset successfully!")
    else:
        logger.error(f"Unknown database command: {command}")
        raise typer.BadParameter(
            f"Unknown database command: {command}. Available commands: init, migrate, reset."
        )


@app.command("version")
def version():
    """
    Show version information.
    """
    import pkg_resources
    version = pkg_resources.get_distribution("mcp_security").version
    typer.echo(f"MCP Security Guardian Tool v{version}")
    typer.echo(f"Environment: {settings.ENVIRONMENT}")


def main():
    """
    Main entry point for the CLI.
    """
    app()


if __name__ == "__main__":
    main() 