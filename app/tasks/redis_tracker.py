import json
from typing import Any

from app.redis_client import async_redis_client
from falcoria_common.redis.redis_task_tracker import BaseAsyncRedisTracker
from falcoria_common.redis.redis_keys import RedisKeyBuilder
from app.logger import logger

from .schemas import NmapTaskMetadata


class AsyncRedisTaskTracker(BaseAsyncRedisTracker):
    def __init__(self, project: str):
        super().__init__(project, async_redis_client)

    async def get_targets(self) -> set[str]:
        """ Retrieve all unique IPs tracked in Redis for the current project."""
        ip_task_map = await self.get_ip_task_map()
        if not ip_task_map:
            logger.warning(f"No IPs found in Redis for project {self.project}.")
            return set()

        ips = {k.decode() if isinstance(k, bytes) else k for k in ip_task_map.keys()}
        logger.info(f"Targets in Redis for project {self.project}: {ips}")
        return ips
    
    async def track_nmap_task(self, task_id: str, project_id: str, user_id: str, ip: str, ports: str) -> Any:
        project_key = RedisKeyBuilder.project_task_ids_key(project_id)      # to track tasks by project
        user_key = RedisKeyBuilder.user_task_ids_key(user_id)               # to track tasks by user
        ip_key = RedisKeyBuilder.project_ip_task_ids_key(project_id, ip)    # to cancel tasks by IP
        meta_key = RedisKeyBuilder.task_metadata_nmap_key(task_id)          # to track metadata, for revocation

        async with self.redis.pipeline() as pipe:
            pipe.sadd(project_key, task_id)
            pipe.sadd(user_key, task_id)
            pipe.sadd(ip_key, task_id)
            pipe.hset(meta_key, mapping={"ip": ip, "ports": ports})
            results = await pipe.execute()

        logger.info(f"Tracked Nmap task {task_id} for project {project_id}, user {user_id}, IP {ip}: {results}")
        return results

    async def get_locked_ips(self, project_id) -> set[str]:
        pattern = RedisKeyBuilder.lock_ip_ports_key(project_id, "*", "*")
        cursor = 0
        locked_ips = set()

        while True:
            cursor, keys = await self.redis.scan(cursor=cursor, match=pattern, count=2000)
            for key in keys:
                parts = key.decode().split(":")
                if len(parts) >= 6:
                    locked_ips.add(parts[4])  # parts = ['lock', 'project', project_id, 'ip', ip, 'ports', ports]
            if cursor == 0:
                break

        return locked_ips

    async def get_task_metadata(self, task_id: str) -> NmapTaskMetadata | None:
        key = RedisKeyBuilder.task_metadata_nmap_key(task_id)
        raw_data = await self.redis.hgetall(key)
        if not raw_data:
            return None

        decoded = {k.decode(): v.decode() for k, v in raw_data.items()}

        try:
            return NmapTaskMetadata(**decoded)
        except Exception as e:
            logger.warning(f"Invalid task metadata for task_id {task_id}: {e}")
            return None


    async def get_running_targets_raw(self) -> list[dict]:
        pattern = RedisKeyBuilder.running_tasks_key("*", "*")
        cursor = 0
        raw_targets = []

        while True:
            cursor, keys = await self.redis.scan(cursor=cursor, match=pattern, count=2000)
            for key in keys:
                entries = await self.redis.lrange(key, 0, -1)
                for entry in entries:
                    try:
                        decoded = json.loads(entry)
                        raw_targets.append(decoded)
                    except Exception as e:
                        logger.warning(f"Invalid JSON in {key}: {e}")
            if cursor == 0:
                break

        return raw_targets
    
    async def get_queued_tasks(self, project_id) -> list[str]:
        project_key = RedisKeyBuilder.project_task_ids_key(project_id) 
        tasks = await self.redis.smembers(project_key)
        return [task.decode() for task in tasks] if tasks else []
    
    async def cleanup_task_metadata(
        self,
        task_id: str,
        project_id: str,
        ip: str,
        port_string: str
    ) -> None:
        # Keys to clean
        project_key = RedisKeyBuilder.project_task_ids_key(project_id)
        user_key = None  # user_id is not available here; optionally skip or include in metadata if needed
        ip_key = RedisKeyBuilder.project_ip_task_ids_key(project_id, ip)
        meta_key = RedisKeyBuilder.task_metadata_nmap_key(task_id)
        lock_key = RedisKeyBuilder.lock_ip_ports_key(project_id, ip, port_string)

        pipe = self.redis.pipeline()
        pipe.srem(project_key, task_id)
        pipe.srem(ip_key, task_id)
        pipe.delete(meta_key)
        pipe.delete(lock_key)
        await pipe.execute()

        logger.info(f"Cleaned up Redis entries for task {task_id}, IP {ip}")
