"""Utilities for rate limiting API requests using Redis.

This module implements a sliding window algorithm to limit requests on a per-key
basis. It exposes helpers to register requests, query remaining quota and
retrieve detailed limit information.  A convenience function,
``check_rate_limit``, combines these helpers and returns both an ``allowed``
flag and a structured info dictionary.
"""
import logging
import time
from typing import Optional

import redis

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
        cost: int = 1
    ) -> bool:
        """
        Check if a request should be rate limited.
        
        Args:
            redis_client: Redis client instance
            key: Rate limiting key (e.g., "rate:ip:192.168.1.1")
            max_requests: Maximum number of requests allowed in the window
            window_seconds: Time window in seconds
            cost: Cost of the current request (default: 1)
            
        Returns:
            bool: True if the request should be rate limited, False otherwise
        """
        now = time.time()
        window_start = now - window_seconds
        
        try:
            # Get the rate limiting pipeline
            async with redis_client.pipeline(transaction=True) as pipe:
                # Remove requests older than the window
                await pipe.zremrangebyscore(key, 0, window_start)
                
                # Count requests in the current window
                await pipe.zcard(key)
                
                # Add current request with timestamp as score
                await pipe.zadd(key, {f"{now}:{cost}": now})
                
                # Set expiration for the key
                await pipe.expire(key, window_seconds * 2)
                
                # Execute pipeline
                _, current_count, _, _ = await pipe.execute()
                
                # Check if rate limit is exceeded
                is_limited = current_count > max_requests
                
                if is_limited:
                    logger.warning(
                        f"Rate limit exceeded for key: {key}",
                        extra={
                            "key": key,
                            "current_count": current_count,
                            "max_requests": max_requests,
                            "window_seconds": window_seconds
                        }
                    )
                
                return is_limited
                
        except Exception as e:
            # In case of Redis errors, log and don't rate limit
            logger.error(
                f"Error in rate limiting: {str(e)}",
                extra={"key": key, "error": str(e)},
                exc_info=True
            )
            return False
    
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

    @staticmethod
    async def check_rate_limit(
        redis_client: Optional[redis.Redis],
        key: str,
        max_requests: int = 100,
        window_seconds: int = 60,
        cost: int = 1,
    ) -> tuple[bool, dict]:
        """Check if a request is allowed and return rate limit information.

        This helper calls :meth:`is_rate_limited` to register the request and
        determines if the caller has exceeded the allotted quota. It then uses
        :meth:`get_remaining_requests` to report how many requests are left in
        the current window.

        Args:
            redis_client: Redis client instance. If ``None``, the request is
                automatically allowed and an empty info dictionary is returned.
            key: Rate limiting key.
            max_requests: Maximum number of requests allowed in the window.
            window_seconds: Duration of the sliding window in seconds.
            cost: Cost of the current request.

        Returns:
            Tuple[bool, dict]: ``True`` if the request is allowed. The info
            dictionary contains at least ``limit`` and ``remaining``. When the
            request is blocked ``retry_after`` gives a rough time until new
            requests may be allowed.
        """

        if redis_client is None:
            # Without a backend we cannot track limits; allow the request.
            return True, {"limit": max_requests, "remaining": max_requests}

        limited = await RateLimiter.is_rate_limited(
            redis_client,
            key,
            max_requests=max_requests,
            window_seconds=window_seconds,
            cost=cost,
        )

        remaining = await RateLimiter.get_remaining_requests(
            redis_client,
            key,
            max_requests=max_requests,
            window_seconds=window_seconds,
        )

        info = {"limit": max_requests, "remaining": remaining}

        if limited:
            info["retry_after"] = window_seconds

        return (not limited, info)
