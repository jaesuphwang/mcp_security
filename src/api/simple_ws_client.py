"""
Minimal WebSocket client for troubleshooting.
"""
import asyncio
import websockets
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("simple_ws_client")


async def hello():
    uri = "ws://localhost:8002"
    async with websockets.connect(uri) as websocket:
        logger.info("Connected to server")
        
        # Send a message
        message = "Hello, server!"
        logger.info(f"Sending: {message}")
        await websocket.send(message)
        
        # Receive response
        response = await websocket.recv()
        logger.info(f"Received: {response}")
        
        # Send another message
        message = "How are you?"
        logger.info(f"Sending: {message}")
        await websocket.send(message)
        
        # Receive response
        response = await websocket.recv()
        logger.info(f"Received: {response}")


async def main():
    try:
        await hello()
        logger.info("Client completed successfully")
    except Exception as e:
        logger.error(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main()) 