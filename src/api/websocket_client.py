"""
Simple WebSocket client to test the WebSocket server.
"""
import asyncio
import json
import logging
import websockets
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("websocket_client")


async def connect_and_test():
    """Connect to the WebSocket server and test the connection."""
    uri = "ws://localhost:8001"
    logger.info(f"Connecting to {uri}")
    
    try:
        # Enable debug logging for websockets
        websockets_logger = logging.getLogger("websockets")
        websockets_logger.setLevel(logging.DEBUG)
        
        # Connect with more debug information
        async with websockets.connect(uri, ping_interval=None) as websocket:
            logger.info("Connected successfully!")
            
            # Wait for the welcome message
            response = await websocket.recv()
            logger.info(f"Received message: {response}")
            
            # Send a simple message
            message = {"type": "ping"}
            logger.info(f"Sending message: {message}")
            await websocket.send(json.dumps(message))
            
            # Wait for response
            response = await websocket.recv()
            logger.info(f"Received response: {response}")
            
            # Sleep to keep the connection open
            logger.info("Sleeping for 5 seconds...")
            await asyncio.sleep(5)
            
            logger.info("WebSocket test completed successfully!")
    
    except websockets.exceptions.ConnectionClosed as e:
        logger.error(f"Connection closed: {e}")
    except Exception as e:
        logger.error(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(connect_and_test()) 