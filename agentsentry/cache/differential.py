import logging
from typing import Dict, Tuple, Optional, Any

# Async redis client library
try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger("AgentSentry.RedisCache")

class SuffixDeltaCompressor:
    def __init__(self, savings_threshold: float = 0.10, redis_url: str = None):
        self.savings_threshold = savings_threshold
        self.redis_url = redis_url
        self.redis_client: Optional[Any] = None
        
        # Local fallback in-memory dictionary
        self.local_store: Dict[str, str] = {}
        
        # Analytics telemetry
        self.cache_hits = 0
        self.cache_misses = 0
        self.estimated_saved_tokens = 0

        if REDIS_AVAILABLE and redis_url:
            self.init_redis()

    def init_redis(self):
        """
        Attempts connection to the Redis distributed database instance.
        """
        try:
            self.redis_client = aioredis.from_url(
                self.redis_url, 
                decode_responses=True, 
                socket_connect_timeout=2
            )
            logger.info(f"Redis cache initialized and connected to: {self.redis_url}")
        except Exception as e:
            logger.warning(f"Failed to connect to Redis ({self.redis_url}). Using local memory fallback. Error: {str(e)}")
            self.redis_client = None

    async def get_cached_content(self, session_id: str) -> Optional[str]:
        """
        Retrieves cached session prompt string from Redis or local store.
        """
        if self.redis_client:
            try:
                # Key namespace formatting
                return await self.redis_client.get(f"agentsentry:session:{session_id}")
            except Exception as e:
                logger.error(f"Redis connection lost during read, failing back to local cache: {str(e)}")
                self.redis_client = None
                
        return self.local_store.get(session_id)

    async def set_cached_content(self, session_id: str, content: str):
        """
        Stores the session prompt string in Redis or local store.
        """
        if self.redis_client:
            try:
                # Store with 24-hour expiration TTL (standard production cache cleanup policy)
                await self.redis_client.set(f"agentsentry:session:{session_id}", content, ex=86400)
                return
            except Exception as e:
                logger.error(f"Redis connection lost during write, failing back to local cache: {str(e)}")
                self.redis_client = None

        self.local_store[session_id] = content

    async def compute_suffix_delta(self, session_id: str, new_content: str) -> Tuple[str, float]:
        """
        Asynchronously computes suffix delta. If prompt prefix matches baseline,
        only transmits changes, saving token transmission load.
        """
        if not new_content:
            return "", 0.0

        previous_content = await self.get_cached_content(session_id)

        if not previous_content:
            await self.set_cached_content(session_id, new_content)
            self.cache_misses += 1
            return new_content, 0.0

        # Check prefix match condition
        if new_content.startswith(previous_content):
            suffix = new_content[len(previous_content):]
            await self.set_cached_content(session_id, new_content)
            self.cache_hits += 1

            saved_chars = len(previous_content)
            savings_ratio = saved_chars / len(new_content)
            
            # Estimate savings
            saved_tokens = int(saved_chars / 4)
            self.estimated_saved_tokens += saved_tokens
            
            return suffix, savings_ratio

        # Fallback on conversation branch divergence
        await self.set_cached_content(session_id, new_content)
        self.cache_misses += 1
        return new_content, 0.0

    async def reset_session(self, session_id: str):
        """
        Deletes stored context for the session.
        """
        if self.redis_client:
            try:
                await self.redis_client.delete(f"agentsentry:session:{session_id}")
            except Exception:
                pass
        
        if session_id in self.local_store:
            del self.local_store[session_id]
