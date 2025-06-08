"""
Minimal WebSocket server for troubleshooting.
"""
import asyncio
import websockets
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("simple_ws_server")


async def echo(websocket):
    try:
        logger.info("Client connected")
        async for message in websocket:
            logger.info(f"Received: {message}")
            await websocket.send(f"Echo: {message}")
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        logger.info("Client disconnected")


async def main():
    async with websockets.serve(echo, "localhost", 8002):
        logger.info("Server started on ws://localhost:8002")
        await asyncio.Future()  # Run forever


if __name__ == "__main__":
    asyncio.run(main()) 