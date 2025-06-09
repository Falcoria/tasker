from app.redis_client import async_redis_client
from app.logger import logger


class RedisTaskTracker:
    def __init__(self, project: str):
        self.project = project
        self.redis = async_redis_client

    def _task_ids_key(self) -> str:
        return f"project:{self.project}:task_ids"

    def _ip_task_map_key(self) -> str:
        return f"project:{self.project}:ip_task_map"

    def _ip_lock_key(self, ip: str) -> str:
        return f"project:{self.project}:ip_task_lock:{ip}"

    async def track_task_id(self, task_id: str):
        await self.redis.rpush(self._task_ids_key(), task_id)

    async def get_task_ids(self):
        return await self.redis.lrange(self._task_ids_key(), 0, -1)

    async def remove_task_id(self, task_id: str):
        await self.redis.lrem(self._task_ids_key(), 0, task_id)

    async def track_ip_task(self, ip: str, task_id: str):
        await self.redis.hset(self._ip_task_map_key(), ip, task_id)

    async def get_ip_task_map(self):
        return await self.redis.hgetall(self._ip_task_map_key())

    async def remove_ip_task(self, ip: str):
        await self.redis.hdel(self._ip_task_map_key(), ip)

    async def acquire_ip_lock(self, ip: str, ttl_seconds: int = 300) -> bool:
        key = f"project:{self.project}:ip_task_lock:{ip}"
        was_set = await self.redis.set(key, "1", ex=ttl_seconds, nx=True)
        return was_set is True

    async def release_ip_lock(self, ip: str):
        key = f"project:{self.project}:ip_task_lock:{ip}"
        await self.redis.delete(key)

    async def get_targets(self) -> set[str]:
        ip_task_map = await self.get_ip_task_map()
        if not ip_task_map:
            logger.warning(f"No IPs found in Redis for project {self.project}.")
            return set()

        ips = {k.decode() if isinstance(k, bytes) else k for k in ip_task_map.keys()}
        logger.info(f"Targets in Redis for project {self.project}: {ips}")
        return ips