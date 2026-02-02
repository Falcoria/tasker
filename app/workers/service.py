import time
import asyncio

from app.redis_client import async_redis_client
from app.celery_app import send_worker_service_task, celery_app
from app.logger import logger
from app.config import config

from .schemas import TaskNames, WorkerIPData
from falcoria_common.redis.redis_worker_tracker import RedisWorkerTracker, RedisKeyBuilder


async def get_all_worker_ips() -> dict[str, WorkerIPData]:
    """
    Returns:
    {
        hostname: WorkerIPData
    }
    """
    tracker = RedisWorkerTracker(async_redis_client)
    raw_data = await tracker.get_worker_data_raw()

    result: dict[str, WorkerIPData] = {}

    for hostname, fields in raw_data.items():
        result[hostname] = WorkerIPData(
            ip=fields.get("ip", "unknown"),
            last_updated=int(fields.get("last_updated", 0)),
            last_seen=int(fields.get("last_seen", 0))  # new field
        )

    return result


async def periodic_update_worker_ip_task(stop_event: asyncio.Event):
    while not stop_event.is_set():
        try:
            logger.info("Running periodic UPDATE_WORKER_IP task (FastAPI lifespan loop)")
            send_worker_service_task(TaskNames.UPDATE_WORKER_IP)
            logger.info("Worker IP registered successfully")
        except Exception as e:
            logger.exception(f"Error in periodic_update_worker_ip_task: {e}")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=config.worker_ip_update_ttl)
        except asyncio.TimeoutError:
            pass



async def periodic_refresh_workers_liveness_task(stop_event: asyncio.Event):
    r = async_redis_client
    interval = 30
    live_ttl = 90

    def _id_to_hostname(worker_id: str) -> str:
        # Extract hostname part from worker id like "celery@hostname"
        return worker_id.split("@", 1)[1] if "@" in worker_id else worker_id

    while not stop_event.is_set():
        try:
            insp = celery_app.control.inspect()
            ping = insp.ping() or {}
            now = int(time.time())
            updated = []

            for worker_id in ping.keys():
                hostname = _id_to_hostname(worker_id)
                key = RedisKeyBuilder.worker_key(hostname)

                # Update only last_seen field in the worker hash
                await r.hset(key, "last_seen", now)
                # Refresh TTL to keep the worker alive in Redis
                await r.expire(key, live_ttl)

                updated.append(hostname)

            logger.debug(f"Live workers refreshed: {updated}")
        except Exception as e:
            logger.exception(f"liveness refresh error: {e}")

        try:
            # Sleep until next check or until stop_event is set
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


def register_periodic_update_worker_ip_task(lifespan_scope_tasks: list):
    """
    Registers periodic_update_worker_ip_task to run in background.
    """
    stop_event = asyncio.Event()
    task = asyncio.create_task(periodic_update_worker_ip_task(stop_event))
    lifespan_scope_tasks.append((task, stop_event))

    stop_event_workers = asyncio.Event()
    task_workers = asyncio.create_task(periodic_refresh_workers_liveness_task(stop_event_workers))
    lifespan_scope_tasks.append((task_workers, stop_event_workers))