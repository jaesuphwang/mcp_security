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
"""Token revocation service for MCP Security Guardian."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from enum import Enum
from typing import Dict, Optional, List, Any

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover - redis is optional for tests
    redis = None  # type: ignore


class RevocationReason(Enum):
    """Standard reasons for token revocation."""

    COMPROMISED = "compromised"
    USER_REQUEST = "user_request"
    ADMINISTRATIVE = "administrative"
    OTHER = "other"


class RevocationPriority(Enum):
    """Priority levels for a revocation request."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TokenRevocationService:
    """Service responsible for managing token revocations."""

    def __init__(self, redis_client: Optional["redis.Redis"] = None) -> None:
        self.redis = redis_client
        self._revocations: Dict[str, Dict[str, Any]] = {}
        self._revoked_tokens: Dict[str, str] = {}

    async def revoke_token(self, token: str, reason: str, revoked_by: str) -> str:
        """Revoke a single token and return a revocation ID."""
        revocation_id = str(uuid.uuid4())
        data = {
            "revocation_id": revocation_id,
            "token": token,
            "reason": reason,
            "revoked_by": revoked_by,
            "revoked_at": datetime.utcnow().isoformat(),
        }

        if self.redis:
            try:
                self.redis.hset(f"revocation:{revocation_id}", mapping=data)
                self.redis.set(f"revoked:{token}", revocation_id)
            except Exception:
                # Fallback to in-memory if Redis fails
                self._revocations[revocation_id] = data
                self._revoked_tokens[token] = revocation_id
        else:
            self._revocations[revocation_id] = data
            self._revoked_tokens[token] = revocation_id

        return revocation_id

    async def is_token_revoked(self, token: str) -> bool:
        """Return True if the token has been revoked."""
        if self.redis:
            try:
                return self.redis.exists(f"revoked:{token}") == 1
            except Exception:
                return token in self._revoked_tokens
        return token in self._revoked_tokens

    async def bulk_revoke_tokens(
        self, tokens: List[str], server_id: str, reason: str
    ) -> Dict[str, Any]:
        """Revoke multiple tokens at once."""
        revocation_ids: List[str] = []
        for token in tokens:
            revocation_id = await self.revoke_token(token, reason, server_id)
            revocation_ids.append(revocation_id)
        return {"revoked_count": len(revocation_ids), "revocation_ids": revocation_ids}

    async def get_revocation(self, revocation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve revocation information by ID."""
        if self.redis:
            try:
                data = self.redis.hgetall(f"revocation:{revocation_id}")
                return data if data else None
            except Exception:
                return self._revocations.get(revocation_id)
        return self._revocations.get(revocation_id)

    def check_health(self) -> bool:
        """Simple health check for the service."""
        if self.redis:
            try:
                return self.redis.ping() is True
            except Exception:
                return False
        return True

