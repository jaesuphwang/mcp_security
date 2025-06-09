#!/usr/bin/env python3
"""Unit tests for the TokenRevocationService."""
import asyncio
import os
import sys
import uuid

# Add the repository src directory to the path so tests can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from revocation.token_revocation import TokenRevocationService


class TokenRevocationServiceTester:
    def __init__(self):
        self.service = TokenRevocationService()
        self.results = []

    def record(self, name: str, passed: bool, details: str):
        self.results.append({"test": name, "passed": passed, "details": details})
        print(f"{'✅' if passed else '❌'} {name}: {details}")

    async def run_tests(self):
        token = "unit-token-" + str(uuid.uuid4())
        rev_id = await self.service.revoke_token(token, "unit test", "tester")
        self.record("revoke_token", bool(rev_id), f"revocation_id={rev_id}")

        revoked = await self.service.is_token_revoked(token)
        self.record("is_token_revoked", revoked, f"revoked={revoked}")

        rev_info = await self.service.get_revocation(rev_id)
        self.record(
            "get_revocation",
            rev_info is not None and rev_info.get("token") == token,
            f"info_found={rev_info is not None}"
        )

        tokens = [f"bulk-{i}" for i in range(3)]
        bulk = await self.service.bulk_revoke_tokens(tokens, "server-1", "bulk test")
        self.record(
            "bulk_revoke_tokens",
            bulk.get("revoked_count") == len(tokens),
            f"revoked_count={bulk.get('revoked_count')}"
        )

        health = self.service.check_health()
        self.record("check_health", health, f"healthy={health}")

    def summary(self):
        passed = sum(1 for r in self.results if r["passed"])
        total = len(self.results)
        print(f"\nTokenRevocationService Tests Passed: {passed}/{total}")


async def main():
    tester = TokenRevocationServiceTester()
    await tester.run_tests()
    tester.summary()


import pytest


@pytest.mark.asyncio
async def test_token_revocation_service():
    tester = TokenRevocationServiceTester()
    await tester.run_tests()
    tester.summary()
    assert all(r["passed"] for r in tester.results)


if __name__ == "__main__":
    asyncio.run(main())
