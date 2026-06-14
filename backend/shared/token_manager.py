"""
Token Manager — Redis-backed access and query token lifecycle.

Access token  : long-lived (1 hour), identifies a user session.
Query token   : short-lived (10 min), scoped to a single query intent.
"""
import secrets
import logging
import sys
from pathlib import Path

import redis

sys.path.append(str(Path(__file__).resolve().parents[1]))
from config.settings import REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, USE_SSL

logger = logging.getLogger(__name__)

# ── Redis connection (module-level singleton) ──────────────────────────────────

def _connect_redis() -> redis.Redis | None:
    try:
        client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,
            ssl=USE_SSL,
            decode_responses=True,
            socket_connect_timeout=3,
        )
        client.ping()
        logger.info("✅ Redis connected at %s:%s", REDIS_HOST, REDIS_PORT)
        return client
    except redis.ConnectionError as exc:
        logger.error("❌ Redis connection failed: %s", exc)
        return None


_redis_client: redis.Redis | None = _connect_redis()


# ── Token Manager ──────────────────────────────────────────────────────────────

class TokenManager:
    """Manages access tokens and query tokens via Redis."""

    ACCESS_TOKEN_TTL = 3600   # seconds (1 hour)
    QUERY_TOKEN_TTL  = 600    # seconds (10 minutes)

    # Redis key prefixes to avoid collisions
    _ACCESS_PREFIX = "access:"
    _QUERY_PREFIX  = "query:"

    def __init__(self):
        self._r = _redis_client
        if not self._r:
            logger.warning("⚠️  TokenManager: Redis unavailable — all auth will fail.")

    def _require_redis(self):
        if not self._r:
            raise RuntimeError("Redis is not connected.")

    # ── Access tokens ──────────────────────────────────────────────────────────

    def generate_access_token(self, user_id: str) -> str:
        self._require_redis()
        token = secrets.token_hex(32)
        self._r.set(f"{self._ACCESS_PREFIX}{token}", user_id, ex=self.ACCESS_TOKEN_TTL)
        logger.info("🔑 Access token generated for user '%s'", user_id)
        return token

    def validate_access_token(self, token: str) -> bool:
        if not self._r or not token:
            return False
        return self._r.exists(f"{self._ACCESS_PREFIX}{token}") == 1

    def get_user_for_token(self, token: str) -> str | None:
        if not self._r:
            return None
        return self._r.get(f"{self._ACCESS_PREFIX}{token}")

    def revoke_access_token(self, token: str) -> None:
        if self._r:
            self._r.delete(f"{self._ACCESS_PREFIX}{token}")

    # ── Query tokens ───────────────────────────────────────────────────────────

    def generate_query_token(self, access_token: str, query: str) -> str:
        self._require_redis()
        if not self.validate_access_token(access_token):
            raise ValueError("Invalid or expired access token.")
        token = secrets.token_hex(32)
        self._r.set(f"{self._QUERY_PREFIX}{token}", access_token, ex=self.QUERY_TOKEN_TTL)
        logger.info("🔑 Query token generated (query=%s)", query)
        return token

    def validate_query_token(self, access_token: str, query_token: str) -> bool:
        """Return True only if the query token exists AND is linked to the given access token."""
        if not self._r or not access_token or not query_token:
            return False
        stored = self._r.get(f"{self._QUERY_PREFIX}{query_token}")
        return stored == access_token

    def revoke_query_token(self, query_token: str) -> None:
        if self._r:
            self._r.delete(f"{self._QUERY_PREFIX}{query_token}")

    # ── Utility ────────────────────────────────────────────────────────────────

    def list_active_tokens(self) -> dict:
        if not self._r:
            return {}
        keys = self._r.keys(f"{self._ACCESS_PREFIX}*")
        return {k: self._r.get(k) for k in keys}
