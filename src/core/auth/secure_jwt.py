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
Enhanced secure JWT authentication module with CSRF protection and secure algorithms.
"""
import os
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
from pydantic import BaseModel, Field

from core.config.settings import Settings
from core.utils.logging import get_logger

logger = get_logger(__name__)

class SecureJWTConfig(BaseModel):
    """Secure JWT configuration."""
    # Only allow secure algorithms
    allowed_algorithms: list = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
    # Token expiration settings
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    api_token_expire_days: int = 30
    # CSRF settings
    csrf_token_length: int = 32
    csrf_header_name: str = "X-CSRF-Token"
    # Security settings
    require_audience: bool = True
    require_issuer: bool = True
    # Key rotation settings
    key_rotation_days: int = 90

class TokenPair(BaseModel):
    """Token pair with CSRF token."""
    access_token: str
    refresh_token: Optional[str] = None
    csrf_token: str
    token_type: str = "Bearer"
    expires_in: int

class SecureJWTManager:
    """Enhanced JWT manager with security best practices."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.config = SecureJWTConfig()
        
        # Initialize keys
        self._private_key = None
        self._public_key = None
        self._algorithm = None
        
        # Initialize with secure algorithm
        self._setup_keys()
        
        # CSRF token storage (in production, use Redis)
        self._csrf_tokens = {}
    
    def _setup_keys(self):
        """Setup cryptographic keys for JWT signing."""
        # Check if RSA keys exist in environment or generate new ones
        if hasattr(self.settings, 'jwt_private_key') and self.settings.jwt_private_key:
            self._private_key = self.settings.jwt_private_key
            self._public_key = self.settings.jwt_public_key
            self._algorithm = "RS256"
        else:
            # Generate RSA key pair for development
            logger.warning("No RSA keys found, generating new keys. This should not happen in production!")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self._private_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            self._public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            self._algorithm = "RS256"
    
    def generate_csrf_token(self) -> str:
        """Generate a secure CSRF token."""
        return secrets.token_urlsafe(self.config.csrf_token_length)
    
    def _generate_jti(self) -> str:
        """Generate a unique JWT ID."""
        return secrets.token_urlsafe(16)
    
    def create_access_token(
        self,
        subject: str,
        roles: list = None,
        organization_id: Optional[str] = None,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> TokenPair:
        """Create a secure access token with CSRF protection."""
        now = datetime.utcnow()
        expires = now + timedelta(minutes=self.config.access_token_expire_minutes)
        jti = self._generate_jti()
        csrf_token = self.generate_csrf_token()
        
        # Base claims
        claims = {
            "sub": subject,
            "iat": now,
            "exp": expires,
            "jti": jti,
            "type": "access",
            "csrf": hashlib.sha256(csrf_token.encode()).hexdigest(),
            "roles": roles or ["user"],
        }
        
        # Add security claims
        if self.config.require_issuer:
            claims["iss"] = self.settings.app_name
        if self.config.require_audience:
            claims["aud"] = [self.settings.app_name, "api"]
        
        # Add optional claims
        if organization_id:
            claims["org_id"] = organization_id
        if additional_claims:
            claims.update(additional_claims)
        
        # Create token
        token = jwt.encode(claims, self._private_key, algorithm=self._algorithm)
        
        # Store CSRF token (in production, use Redis with expiration)
        self._csrf_tokens[jti] = csrf_token
        
        return TokenPair(
            access_token=token,
            csrf_token=csrf_token,
            expires_in=self.config.access_token_expire_minutes * 60
        )
    
    def create_refresh_token(
        self,
        subject: str,
        organization_id: Optional[str] = None
    ) -> str:
        """Create a secure refresh token."""
        now = datetime.utcnow()
        expires = now + timedelta(days=self.config.refresh_token_expire_days)
        jti = self._generate_jti()
        
        claims = {
            "sub": subject,
            "iat": now,
            "exp": expires,
            "jti": jti,
            "type": "refresh",
        }
        
        if self.config.require_issuer:
            claims["iss"] = self.settings.app_name
        if organization_id:
            claims["org_id"] = organization_id
        
        return jwt.encode(claims, self._private_key, algorithm=self._algorithm)
    
    def verify_token(
        self,
        token: str,
        token_type: str = "access",
        verify_csrf: bool = True,
        csrf_token: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Verify a token with enhanced security checks."""
        try:
            # Decode token
            options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "require": ["sub", "iat", "exp", "jti", "type"]
            }
            
            if self.config.require_issuer:
                options["verify_iss"] = True
                options["require"].append("iss")
            
            if self.config.require_audience:
                options["verify_aud"] = True
                options["require"].append("aud")
            
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=[self._algorithm],
                options=options,
                issuer=self.settings.app_name if self.config.require_issuer else None,
                audience=[self.settings.app_name, "api"] if self.config.require_audience else None
            )
            
            # Verify token type
            if claims.get("type") != token_type:
                return False, None, f"Invalid token type: expected {token_type}"
            
            # Verify CSRF token for access tokens
            if token_type == "access" and verify_csrf:
                if not csrf_token:
                    return False, None, "CSRF token required"
                
                jti = claims.get("jti")
                stored_csrf = self._csrf_tokens.get(jti)
                
                if not stored_csrf or stored_csrf != csrf_token:
                    return False, None, "Invalid CSRF token"
                
                # Also verify the hash in the token
                csrf_hash = hashlib.sha256(csrf_token.encode()).hexdigest()
                if claims.get("csrf") != csrf_hash:
                    return False, None, "CSRF token mismatch"
            
            # Check if token is blacklisted (implement with Redis in production)
            # if await self.is_token_blacklisted(claims.get("jti")):
            #     return False, None, "Token has been revoked"
            
            return True, claims, None
            
        except jwt.ExpiredSignatureError:
            return False, None, "Token has expired"
        except jwt.InvalidTokenError as e:
            return False, None, f"Invalid token: {str(e)}"
        except Exception as e:
            logger.error(f"Error verifying token: {str(e)}")
            return False, None, "Token verification failed"
    
    def revoke_token(self, jti: str):
        """Revoke a token by its JTI."""
        # In production, add to Redis blacklist with TTL
        if jti in self._csrf_tokens:
            del self._csrf_tokens[jti]
    
    def rotate_keys(self):
        """Rotate JWT signing keys."""
        # In production, implement key rotation strategy
        # 1. Generate new keys
        # 2. Keep old keys for verification during transition
        # 3. Sign new tokens with new keys
        # 4. After transition period, remove old keys
        logger.info("Key rotation initiated")
        self._setup_keys()

# Singleton instance
_secure_jwt_manager = None

def get_secure_jwt_manager(settings: Settings) -> SecureJWTManager:
    """Get or create secure JWT manager instance."""
    global _secure_jwt_manager
    if _secure_jwt_manager is None:
        _secure_jwt_manager = SecureJWTManager(settings)
    return _secure_jwt_manager