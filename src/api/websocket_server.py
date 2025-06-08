"""
WebSocket server for MCP Security Guardian.

This module provides a simple WebSocket server that listens on port 8001 for
real-time communication with clients.
"""
import asyncio
import json
import logging
import signal
import sys
import traceback
import websockets
from datetime import datetime
from typing import Dict, Set, Any

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for more information
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("websocket_server")

# Track connected clients
connected_clients = set()


async def handle_client(websocket, path):
    """Handle a client connection."""
    # Generate a unique client ID
    client_id = f"client_{len(connected_clients) + 1}"
    
    # Add the client to our set
    connected_clients.add(websocket)
    logger.info(f"Client {client_id} connected. Path: {path}")
    
    try:
        # Send a welcome message
        welcome_message = {
            "type": "connection_established",
            "client_id": client_id,
            "message": "Welcome to MCP Security Guardian WebSocket server!",
            "timestamp": datetime.now().isoformat()
        }
        welcome_json = json.dumps(welcome_message)
        logger.debug(f"Sending welcome message: {welcome_json}")
        await websocket.send(welcome_json)
        
        # Handle messages
        async for message in websocket:
            logger.info(f"Received message from {client_id}: {message}")
            
            try:
                # Parse the JSON message
                data = json.loads(message)
                logger.debug(f"Parsed message data: {data}")
                
                # Process based on message type
                if "type" in data:
                    if data["type"] == "ping":
                        # Respond to ping
                        pong_message = {
                            "type": "pong",
                            "timestamp": datetime.now().isoformat()
                        }
                        pong_json = json.dumps(pong_message)
                        logger.debug(f"Sending pong message: {pong_json}")
                        await websocket.send(pong_json)
                    elif data["type"] == "subscribe":
                        # Handle subscription
                        channels = data.get("channels", [])
                        subscription_message = {
                            "type": "subscription_result",
                            "status": "success",
                            "channels": channels,
                            "message": f"Subscribed to {len(channels)} channels"
                        }
                        subscription_json = json.dumps(subscription_message)
                        logger.debug(f"Sending subscription result: {subscription_json}")
                        await websocket.send(subscription_json)
                    else:
                        # Echo unknown messages back
                        echo_message = {
                            "type": "echo",
                            "original_message": data,
                            "timestamp": datetime.now().isoformat()
                        }
                        echo_json = json.dumps(echo_message)
                        logger.debug(f"Sending echo message: {echo_json}")
                        await websocket.send(echo_json)
                else:
                    # Message without a type
                    error_message = {
                        "type": "error",
                        "error": "missing_message_type",
                        "message": "Message type is required"
                    }
                    error_json = json.dumps(error_message)
                    logger.debug(f"Sending error message: {error_json}")
                    await websocket.send(error_json)
            except json.JSONDecodeError as e:
                # Not a valid JSON message
                logger.warning(f"Invalid JSON from client {client_id}: {e}")
                error_message = {
                    "type": "error",
                    "error": "invalid_json",
                    "message": "Invalid JSON message"
                }
                error_json = json.dumps(error_message)
                logger.debug(f"Sending error message: {error_json}")
                await websocket.send(error_json)
            except Exception as e:
                # Other processing error
                logger.error(f"Error processing message from {client_id}: {e}")
                logger.error(traceback.format_exc())
                error_message = {
                    "type": "error",
                    "error": "processing_error",
                    "message": f"Error processing message: {str(e)}"
                }
                error_json = json.dumps(error_message)
                logger.debug(f"Sending error message: {error_json}")
                await websocket.send(error_json)
    
    except websockets.exceptions.ConnectionClosed as e:
        logger.info(f"Client {client_id} disconnected: {e}")
    except Exception as e:
        logger.error(f"Error handling client {client_id}: {e}")
        logger.error(traceback.format_exc())
    finally:
        # Remove the client from our set
        if websocket in connected_clients:
            connected_clients.remove(websocket)
            logger.info(f"Client {client_id} removed from connected clients")


async def broadcast_message(message: Dict[str, Any]):
    """Broadcast a message to all connected clients."""
    if not connected_clients:
        logger.info("No connected clients to broadcast to")
        return
    
    # Convert the message to JSON
    message_json = json.dumps(message)
    
    # Send to all connected clients
    disconnected_clients = set()
    for client in connected_clients:
        try:
            await client.send(message_json)
        except websockets.exceptions.ConnectionClosed:
            # Mark for removal
            disconnected_clients.add(client)
        except Exception as e:
            logger.error(f"Error sending broadcast: {e}")
            logger.error(traceback.format_exc())
    
    # Remove disconnected clients
    for client in disconnected_clients:
        if client in connected_clients:
            connected_clients.remove(client)
    
    logger.info(f"Broadcast message sent to {len(connected_clients)} clients")


async def start_server():
    """Start the WebSocket server."""
    # Create a server
    try:
        server = await websockets.serve(
            handle_client,
            "0.0.0.0",  # Listen on all available network interfaces
            8001,       # Use port 8001 to avoid conflict with the main API
            ping_interval=None,  # Disable automatic pings
            max_size=10 * 1024 * 1024  # 10MB max message size
        )
        
        logger.info("WebSocket server started on ws://0.0.0.0:8001")
        
        # Set up signal handlers for graceful shutdown
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(server)))
        
        # Keep the server running
        await asyncio.Future()
    except Exception as e:
        logger.error(f"Error starting WebSocket server: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)


async def shutdown(server):
    """Shut down the server gracefully."""
    logger.info("Shutting down WebSocket server...")
    
    # Close all client connections
    for client in connected_clients:
        try:
            await client.close(1001, "Server shutting down")
        except Exception as e:
            logger.error(f"Error closing client connection: {e}")
    
    # Close the server
    server.close()
    await server.wait_closed()
    
    # Stop the event loop
    asyncio.get_event_loop().stop()
    logger.info("WebSocket server shut down")


def run_server():
    """Run the WebSocket server."""
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        logger.info("Server stopped by keyboard interrupt")
    except Exception as e:
        logger.error(f"Error running server: {e}")
        logger.error(traceback.format_exc())
    finally:
        logger.info("Server stopped")


if __name__ == "__main__":
    run_server() 