"""
JWT authentication module for MCP Security Guardian Tool.
"""
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Union, Any, List, Tuple

import jwt
import redis
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import PyJWTError, InvalidTokenError, ExpiredSignatureError
from pydantic import BaseModel, Field, validator

from core.config import Settings, get_settings
from core.database import get_redis

# Configure logger
logger = logging.getLogger("mcp_security.auth.jwt")

# OAuth2 Bearer token scheme for different endpoints
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/token")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="api/auth/token", auto_error=False)


# Rate limiting configuration
class RateLimitConfig:
    """Configuration for rate limiting."""
    # Login attempts
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_WINDOW_SECONDS = 300  # 5 minutes
    
    # Token refresh
    REFRESH_MAX_ATTEMPTS = 10
    REFRESH_WINDOW_SECONDS = 3600  # 1 hour
    
    # Token blacklisting
    BLACKLIST_KEY_PREFIX = "token:blacklist:"
    BLACKLIST_EXPIRE_SECONDS = 86400 * 7  # 7 days


class TokenType(str):
    """Token type enum."""
    ACCESS = "access"
    REFRESH = "refresh"
    RESET = "reset"
    API = "api"


class TokenData(BaseModel):
    """
    Token data model.
    """
    # Essential claims
    sub: str = Field(..., description="Subject (user ID)")
    exp: datetime = Field(..., description="Expiration time")
    iat: datetime = Field(..., description="Issued at time")
    jti: str = Field(..., description="JWT ID (unique identifier)")
    
    # Token metadata
    type: str = Field(..., description="Token type (access, refresh, etc.)")
    role: str = Field(default="user", description="User role")
    
    # Additional optional claims
    iss: Optional[str] = Field(None, description="Issuer")
    aud: Optional[List[str]] = Field(None, description="Audience")
    nbf: Optional[datetime] = Field(None, description="Not valid before time")
    scope: Optional[str] = Field(None, description="Token scope")
    
    # Custom claims
    organization_id: Optional[str] = Field(None, description="Organization ID")
    session_id: Optional[str] = Field(None, description="Session ID")
    device_id: Optional[str] = Field(None, description="Device ID")
    ip_address: Optional[str] = Field(None, description="IP address")
    user_agent: Optional[str] = Field(None, description="User agent")
    
    @validator("role")
    def validate_role(cls, v):
        """Validate role is a known value."""
        allowed_roles = ["user", "admin", "service", "system"]
        if v not in allowed_roles:
            raise ValueError(f"Role must be one of {allowed_roles}")
        return v


def create_token(
    data: Dict[str, Any],
    token_type: str,
    settings: Settings,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None
) -> str:
    """
    Create a JWT token with the specified type and claims.

    Args:
        data: Base data to encode in the token.
        token_type: Type of token (access, refresh, etc.).
        settings: Application settings.
        expires_delta: Optional expiration delta.
        additional_claims: Additional claims to include in the token.

    Returns:
        JWT token string.
    """
    to_encode = data.copy()
    
    # Set token expiration time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        if token_type == TokenType.ACCESS:
            expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRES_MINUTES)
        elif token_type == TokenType.REFRESH:
            expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRES_DAYS)
        elif token_type == TokenType.RESET:
            expire = datetime.utcnow() + timedelta(hours=settings.PASSWORD_RESET_TOKEN_EXPIRES_HOURS)
        elif token_type == TokenType.API:
            # API tokens can have custom expiration or no expiration
            expire = data.get("exp", datetime.utcnow() + timedelta(days=30))
        else:
            # Default expiration for unknown token types
            expire = datetime.utcnow() + timedelta(hours=1)
    
    # Add standard claims
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": token_type,
        "jti": str(uuid.uuid4())
    })
    
    # Add issuer if configured
    if settings.APP_NAME:
        to_encode["iss"] = settings.APP_NAME
    
    # Add additional claims if provided
    if additional_claims:
        to_encode.update(additional_claims)
    
    # Encode the token
    try:
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.JWT_SECRET, 
            algorithm=settings.JWT_ALGORITHM
        )
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error encoding JWT: {str(e)}")
        raise


def create_access_token(
    data: Dict[str, Any], 
    settings: Optional[Settings] = None,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None
) -> str:
    """
    Create a JWT access token.

    Args:
        data: Data to encode in the token.
        settings: Application settings.
        expires_delta: Optional expiration delta.
        additional_claims: Additional claims to include in the token.

    Returns:
        JWT token string.
    """
    if settings is None:
        settings = get_settings()
    
    return create_token(
        data=data,
        token_type=TokenType.ACCESS,
        settings=settings,
        expires_delta=expires_delta,
        additional_claims=additional_claims
    )


def create_refresh_token(
    data: Dict[str, Any], 
    settings: Optional[Settings] = None,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None
) -> str:
    """
    Create a JWT refresh token.

    Args:
        data: Data to encode in the token.
        settings: Application settings.
        expires_delta: Optional expiration delta.
        additional_claims: Additional claims to include in the token.

    Returns:
        JWT token string.
    """
    if settings is None:
        settings = get_settings()
    
    return create_token(
        data=data,
        token_type=TokenType.REFRESH,
        settings=settings,
        expires_delta=expires_delta,
        additional_claims=additional_claims
    )


def create_api_token(
    data: Dict[str, Any], 
    settings: Optional[Settings] = None,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None
) -> str:
    """
    Create a JWT API token.

    Args:
        data: Data to encode in the token.
        settings: Application settings.
        expires_delta: Optional expiration delta.
        additional_claims: Additional claims to include in the token.

    Returns:
        JWT token string.
    """
    if settings is None:
        settings = get_settings()
    
    return create_token(
        data=data,
        token_type=TokenType.API,
        settings=settings,
        expires_delta=expires_delta,
        additional_claims=additional_claims
    )


def create_password_reset_token(
    data: Dict[str, Any], 
    settings: Optional[Settings] = None,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None
) -> str:
    """
    Create a JWT password reset token.

    Args:
        data: Data to encode in the token.
        settings: Application settings.
        expires_delta: Optional expiration delta.
        additional_claims: Additional claims to include in the token.

    Returns:
        JWT token string.
    """
    if settings is None:
        settings = get_settings()
    
    return create_token(
        data=data,
        token_type=TokenType.RESET,
        settings=settings,
        expires_delta=expires_delta,
        additional_claims=additional_claims
    )


async def is_token_blacklisted(jti: str, redis_client: redis.Redis) -> bool:
    """
    Check if a token is blacklisted.

    Args:
        jti: JWT ID to check.
        redis_client: Redis client.

    Returns:
        True if the token is blacklisted, False otherwise.
    """
    blacklist_key = f"{RateLimitConfig.BLACKLIST_KEY_PREFIX}{jti}"
    return bool(await redis_client.exists(blacklist_key))


async def blacklist_token(
    jti: str, 
    expires_at: datetime, 
    redis_client: redis.Redis,
    reason: str = "revoked"
) -> bool:
    """
    Blacklist a token.

    Args:
        jti: JWT ID to blacklist.
        expires_at: Token expiration timestamp.
        redis_client: Redis client.
        reason: Reason for blacklisting.

    Returns:
        True if the token was successfully blacklisted, False otherwise.
    """
    blacklist_key = f"{RateLimitConfig.BLACKLIST_KEY_PREFIX}{jti}"
    
    # Calculate TTL (time to live) for the blacklist entry
    # The entry should expire after the token would expire, plus some buffer
    now = datetime.utcnow()
    if expires_at > now:
        ttl = int((expires_at - now).total_seconds()) + 60  # Add 60 seconds buffer
        ttl = min(ttl, RateLimitConfig.BLACKLIST_EXPIRE_SECONDS)  # Cap at maximum
    else:
        # If token is already expired, store for a shorter time
        ttl = 3600  # 1 hour
    
    # Store token in blacklist with reason and expiry
    try:
        await redis_client.set(
            blacklist_key, 
            reason,
            ex=ttl
        )
        return True
    except Exception as e:
        logger.error(f"Error blacklisting token: {str(e)}")
        return False


async def decode_token(
    token: str,
    settings: Optional[Settings] = None,
    verify_exp: bool = True,
    verify_type: Optional[str] = None,
    check_blacklist: bool = True
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Decode and verify a JWT token.

    Args:
        token: JWT token to decode.
        settings: Application settings.
        verify_exp: Whether to verify token expiration.
        verify_type: Token type to verify.
        check_blacklist: Whether to check if the token is blacklisted.

    Returns:
        Tuple of (success, payload, error_message).
    """
    if settings is None:
        settings = get_settings()
    
    try:
        # Decode token
        payload = jwt.decode(
            token, 
            settings.JWT_SECRET, 
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": verify_exp}
        )
        
        # Check token type if specified
        if verify_type and payload.get("type") != verify_type:
            return False, None, f"Invalid token type: expected {verify_type}, got {payload.get('type')}"
        
        # Check if token is blacklisted
        if check_blacklist and "jti" in payload:
            redis_client = get_redis()
            if await is_token_blacklisted(payload["jti"], redis_client):
                return False, None, "Token has been revoked"
        
        return True, payload, None
        
    except ExpiredSignatureError:
        return False, None, "Token has expired"
    except InvalidTokenError as e:
        return False, None, f"Invalid token: {str(e)}"
    except Exception as e:
        logger.error(f"Error decoding token: {str(e)}")
        return False, None, "Error decoding token"


async def verify_token(
    token: str = Depends(oauth2_scheme),
    settings: Settings = Depends(get_settings),
    redis_client: redis.Redis = Depends(get_redis)
) -> TokenData:
    """
    Verify and decode a JWT access token.

    Args:
        token: JWT token to verify.
        settings: Application settings.
        redis_client: Redis client.

    Returns:
        TokenData object with decoded information.

    Raises:
        HTTPException: If token is invalid or expired.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Decode token
    success, payload, error_message = await decode_token(
        token=token,
        settings=settings,
        verify_exp=True,
        verify_type=TokenType.ACCESS,
        check_blacklist=True
    )
    
    if not success:
        logger.warning(f"Token verification failed: {error_message}")
        raise credentials_exception
    
    # Convert timestamps to datetime objects
    try:
        exp = datetime.fromtimestamp(payload.get("exp"))
        iat = datetime.fromtimestamp(payload.get("iat"))
        nbf = datetime.fromtimestamp(payload.get("nbf")) if "nbf" in payload else None
        
        # Extract required fields
        sub = payload.get("sub")
        jti = payload.get("jti")
        token_type = payload.get("type")
        
        if not sub or not jti:
            raise credentials_exception
        
        # Create TokenData object
        token_data = TokenData(
            sub=sub,
            exp=exp,
            iat=iat,
            jti=jti,
            type=token_type,
            role=payload.get("role", "user"),
            iss=payload.get("iss"),
            aud=payload.get("aud"),
            nbf=nbf,
            scope=payload.get("scope"),
            organization_id=payload.get("organization_id"),
            session_id=payload.get("session_id"),
            device_id=payload.get("device_id"),
            ip_address=payload.get("ip_address"),
            user_agent=payload.get("user_agent")
        )
        
        return token_data
        
    except Exception as e:
        logger.error(f"Error parsing token data: {str(e)}")
        raise credentials_exception


async def verify_refresh_token(
    token: str,
    settings: Settings = Depends(get_settings),
    redis_client: redis.Redis = Depends(get_redis)
) -> TokenData:
    """
    Verify and decode a JWT refresh token.

    Args:
        token: JWT refresh token to verify.
        settings: Application settings.
        redis_client: Redis client.

    Returns:
        TokenData object with decoded information.

    Raises:
        HTTPException: If token is invalid or expired.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Decode token
    success, payload, error_message = await decode_token(
        token=token,
        settings=settings,
        verify_exp=True,
        verify_type=TokenType.REFRESH,
        check_blacklist=True
    )
    
    if not success:
        logger.warning(f"Refresh token verification failed: {error_message}")
        raise credentials_exception
    
    # Convert timestamps to datetime objects
    try:
        exp = datetime.fromtimestamp(payload.get("exp"))
        iat = datetime.fromtimestamp(payload.get("iat"))
        nbf = datetime.fromtimestamp(payload.get("nbf")) if "nbf" in payload else None
        
        # Extract required fields
        sub = payload.get("sub")
        jti = payload.get("jti")
        token_type = payload.get("type")
        
        if not sub or not jti:
            raise credentials_exception
        
        # Create TokenData object
        token_data = TokenData(
            sub=sub,
            exp=exp,
            iat=iat,
            jti=jti,
            type=token_type,
            role=payload.get("role", "user"),
            iss=payload.get("iss"),
            aud=payload.get("aud"),
            nbf=nbf,
            scope=payload.get("scope"),
            organization_id=payload.get("organization_id"),
            session_id=payload.get("session_id"),
            device_id=payload.get("device_id"),
            ip_address=payload.get("ip_address"),
            user_agent=payload.get("user_agent")
        )
        
        return token_data
        
    except Exception as e:
        logger.error(f"Error parsing refresh token data: {str(e)}")
        raise credentials_exception


async def verify_optional_token(
    token: Optional[str] = Depends(oauth2_scheme_optional),
    settings: Settings = Depends(get_settings),
    redis_client: redis.Redis = Depends(get_redis)
) -> Optional[TokenData]:
    """
    Verify an optional JWT token.

    Args:
        token: Optional JWT token to verify.
        settings: Application settings.
        redis_client: Redis client.

    Returns:
        TokenData object if token is valid, None otherwise.
    """
    if not token:
        return None
    
    try:
        return await verify_token(token, settings, redis_client)
    except HTTPException:
        return None


async def get_current_user(
    token_data: TokenData = Depends(verify_token),
    request: Request = None
) -> Dict[str, Any]:
    """
    Get current user from token data.

    Args:
        token_data: TokenData from verified token.
        request: FastAPI request object for additional context.

    Returns:
        Dictionary with user information.
    """
    # Basic user information from token
    user_info = {
        "id": token_data.sub,
        "role": token_data.role,
        "organization_id": token_data.organization_id
    }
    
    # Add token metadata
    user_info["token"] = {
        "jti": token_data.jti,
        "exp": token_data.exp.isoformat(),
        "iat": token_data.iat.isoformat(),
        "type": token_data.type
    }
    
    # Add request context if available
    if request:
        user_info["ip"] = request.client.host if request.client else None
        user_info["user_agent"] = request.headers.get("user-agent")
    
    return user_info


async def get_admin_user(
    token_data: TokenData = Depends(verify_token),
    request: Request = None
) -> Dict[str, Any]:
    """
    Get current admin user from token data.

    Args:
        token_data: TokenData from verified token.
        request: FastAPI request object for additional context.

    Returns:
        Dictionary with admin user information.

    Raises:
        HTTPException: If user is not an admin.
    """
    if token_data.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Admin role required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return await get_current_user(token_data, request) 