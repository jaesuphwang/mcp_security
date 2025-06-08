"""
Rate limiting utility for the MCP Security Guardian API.
Provides flexible rate limiting based on keys with Redis backend.
"""
import logging
import time
from typing import Optional

import redis.asyncio as redis

logger = logging.getLogger("mcp_security.utils.rate_limiting")


class RateLimiter:
    """
    Implements a sliding window rate limiter using Redis.
    
    This allows limiting API requests based on various keys (IP, user ID, etc.)
    within a defined time window.
    """
    
    @staticmethod
    async def is_rate_limited(
        redis_client: redis.Redis,
        key: str,
        max_requests: int = 100,
        window_seconds: int = 60,
        cost: int = 1,
    ) -> bool:
        """Return ``True`` if the request should be rate limited."""

        allowed, _ = await RateLimiter.check_rate_limit(
            redis_client,
            key,
            max_requests=max_requests,
            window_seconds=window_seconds,
            cost=cost,
        )
        return not allowed

    @staticmethod
    async def check_rate_limit(
        redis_client: redis.Redis,
        key: str,
        max_requests: int = 100,
        window_seconds: int = 60,
        cost: int = 1,
    ) -> tuple:
        """Atomically check and update rate limit for a key.

        Returns a tuple of (allowed, info dict).
        """
        now = time.time()
        window_start = now - window_seconds

        try:
            async with redis_client.pipeline(transaction=True) as pipe:
                await pipe.zremrangebyscore(key, 0, window_start)
                await pipe.zcard(key)
                await pipe.zadd(key, {f"{now}:{cost}": now})
                await pipe.expire(key, window_seconds * 2)
                _, current_count, _, _ = await pipe.execute()

            current_count += cost
            remaining = max(0, max_requests - current_count)
            allowed = current_count <= max_requests

            retry_after = None
            if not allowed:
                oldest = await redis_client.zrange(key, 0, 0, withscores=True)
                oldest_ts = oldest[0][1] if oldest else now
                retry_after = max(0, window_seconds - (now - oldest_ts))

            return allowed, {
                "limit": max_requests,
                "remaining": remaining,
                "retry_after": retry_after,
            }

        except Exception as e:
            logger.error(
                f"Error checking rate limit: {str(e)}",
                extra={"key": key, "error": str(e)},
                exc_info=True,
            )
            return True, {
                "limit": max_requests,
                "remaining": max_requests,
                "error": str(e),
            }
    
    @staticmethod
    async def get_remaining_requests(
        redis_client: redis.Redis,
        key: str,
        max_requests: int = 100,
        window_seconds: int = 60
    ) -> int:
        """
        Get the number of remaining requests allowed for a key.
        
        Args:
            redis_client: Redis client instance
            key: Rate limiting key
            max_requests: Maximum number of requests allowed in the window
            window_seconds: Time window in seconds
            
        Returns:
            int: Number of remaining requests (0 if rate limited)
        """
        now = time.time()
        window_start = now - window_seconds
        
        try:
            # Remove requests older than the window
            await redis_client.zremrangebyscore(key, 0, window_start)
            
            # Count requests in the current window
            current_count = await redis_client.zcard(key)
            
            # Calculate remaining requests
            remaining = max(0, max_requests - current_count)
            
            return remaining
            
        except Exception as e:
            # In case of Redis errors, log and assume no rate limiting
            logger.error(
                f"Error getting remaining requests: {str(e)}",
                extra={"key": key, "error": str(e)},
                exc_info=True
            )
            return max_requests
    
    @staticmethod
    async def reset_rate_limit(
        redis_client: redis.Redis,
        key: str
    ) -> bool:
        """
        Reset the rate limit for a key.
        
        Args:
            redis_client: Redis client instance
            key: Rate limiting key to reset
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Delete the key
            await redis_client.delete(key)
            return True
            
        except Exception as e:
            # In case of Redis errors, log and return False
            logger.error(
                f"Error resetting rate limit: {str(e)}",
                extra={"key": key, "error": str(e)},
                exc_info=True
            )
            return False
    
    @staticmethod
    async def get_rate_limit_info(
        redis_client: redis.Redis,
        key: str,
        max_requests: int = 100,
        window_seconds: int = 60
    ) -> dict:
        """
        Get detailed information about a rate limit key.
        
        Args:
            redis_client: Redis client instance
            key: Rate limiting key
            max_requests: Maximum number of requests allowed in the window
            window_seconds: Time window in seconds
            
        Returns:
            dict: Rate limit information
        """
        now = time.time()
        window_start = now - window_seconds
        
        try:
            # Remove requests older than the window
            await redis_client.zremrangebyscore(key, 0, window_start)
            
            # Count requests in the current window
            current_count = await redis_client.zcard(key)
            
            # Get the oldest request timestamp
            oldest_request = await redis_client.zrange(key, 0, 0, withscores=True)
            oldest_timestamp = oldest_request[0][1] if oldest_request else now
            
            # Calculate time until window resets
            if current_count > 0:
                reset_after = max(0, window_seconds - (now - oldest_timestamp))
            else:
                reset_after = 0
            
            # Calculate remaining requests
            remaining = max(0, max_requests - current_count)
            
            return {
                "key": key,
                "current_count": current_count,
                "max_requests": max_requests,
                "remaining": remaining,
                "window_seconds": window_seconds,
                "reset_after": reset_after,
                "is_limited": current_count >= max_requests
            }
            
        except Exception as e:
            # In case of Redis errors, log and return default info
            logger.error(
                f"Error getting rate limit info: {str(e)}",
                extra={"key": key, "error": str(e)},
                exc_info=True
            )
            return {
                "key": key,
                "current_count": 0,
                "max_requests": max_requests,
                "remaining": max_requests,
                "window_seconds": window_seconds,
                "reset_after": 0,
                "is_limited": False,
                "error": str(e)
            } 