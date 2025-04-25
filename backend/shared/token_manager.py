import redis
import logging
import os
import secrets
import socket

# ✅ Set IS_CLOUD to False since you want to connect to local Redis
IS_CLOUD = False

# ✅ Configure Redis Connection for Local Redis
REDIS_HOST = "localhost" if not IS_CLOUD else "securestorage-redis.redis.cache.windows.net"
REDIS_PORT = 6379 if not IS_CLOUD else 6380
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
USE_SSL = IS_CLOUD  # Only enable SSL for Azure Redis

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ✅ Redis Connection Logic
try:
    logging.info(f"🚀 Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}")
    r = redis.StrictRedis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        ssl=USE_SSL,
        ssl_cert_reqs=None if USE_SSL else None
    )
    r.ping()  # Test connection
    logging.info("✅ Redis Connection Successful!")
except redis.ConnectionError as e:
    logging.error(f"❌ Redis Connection Failed: {e}")
    r = None

class TokenManager:
    def __init__(self):
        """Initialize Token Manager with Redis Connection"""
        if r:
            self.redis_client = r
        else:
            self.redis_client = None  # Redis client not initialized due to connection failure
            logging.warning("⚠️ Redis not available. Fallback to other storage mechanisms.")

    def generate_access_token(self, user_id):
        """Generate and store an access token for a user."""
        if not self.redis_client:
            raise Exception("❌ Redis is not connected!")

        token = secrets.token_hex(32)
        self.redis_client.set(token, user_id, ex=3600)  # Token expires in 1 hour
        return token

    def validate_access_token(self, token):
        """Check if an access token exists in Redis."""
        return self.redis_client.exists(token) == 1 if self.redis_client else False

    def revoke_tokens_for_user(self, user_id):
        """Revoke all access tokens associated with a user."""
        if not self.redis_client:
            return False

        keys = self.redis_client.keys("*")
        for key in keys:
            if self.redis_client.get(key) == user_id:
                self.redis_client.delete(key)

    def generate_query_token(self, access_token, query):
        """Generate a temporary query token linked to an access token."""
        if not self.validate_access_token(access_token):
            raise ValueError("❌ Invalid access token")

        query_token = secrets.token_hex(32)
        self.redis_client.set(query_token, access_token, ex=600)  # Query token expires in 10 minutes
        return query_token

    def validate_query_token(self, access_token, query_token):
        """Validate if a query token is linked to the provided access token."""
        stored_access_token = self.redis_client.get(query_token)
        # ✅ Convert Redis bytes response to a string
        if stored_access_token:
            stored_access_token = stored_access_token.decode("utf-8")
            return stored_access_token == access_token

    def revoke_query_token(self, query_token):
        """Revoke a specific query token."""
        if self.redis_client:
            self.redis_client.delete(query_token)

    def list_active_tokens(self):
        """Retrieve a list of active tokens stored in Redis."""
        if not self.redis_client:
            return {}
        return {key: self.redis_client.get(key) for key in self.redis_client.keys("*")}
