import asyncio
import uuid
import pytest

try:
    from revocation.token_revocation import TokenRevocationService
except Exception:  # pragma: no cover - service may not be available
    TokenRevocationService = None  # type: ignore





def skip_if_service_missing():
    if TokenRevocationService is None:
        pytest.skip("TokenRevocationService not available")


def get_service():
    skip_if_service_missing()
    return TokenRevocationService()


def test_revoke_token():
    service = get_service()
    token = f"test-token-{uuid.uuid4()}"
    async def run():
        revocation_id = await service.revoke_token(token=token, reason="test", revoked_by="pytest")
        assert revocation_id
        assert await service.is_token_revoked(token)
    asyncio.run(run())


def test_bulk_revoke_tokens():
    service = get_service()
    tokens = [f"bulk-{i}-{uuid.uuid4()}" for i in range(3)]
    async def run():
        result = await service.bulk_revoke_tokens(tokens=tokens, server_id="test-server", reason="bulk")
        assert result.get("revoked_count") == len(tokens)
        statuses = await asyncio.gather(*[service.is_token_revoked(t) for t in tokens])
        assert all(statuses)
    asyncio.run(run())


def test_get_revocation_status():
    service = get_service()
    token = f"status-{uuid.uuid4()}"
    async def run():
        revocation_id = await service.revoke_token(token=token, reason="status", revoked_by="pytest")
        revocation = await service.get_revocation(revocation_id)
        assert revocation is not None
        assert getattr(revocation, "revocation_id", None) == revocation_id
    asyncio.run(run())

