import json
import asyncio
from typing import Dict

from app.redis_client import async_redis_client
from app.celery_app import send_worker_service_task
from app.logger import logger
from app.config import config

from .schemas import TaskNames, WorkerIPData
from falcoria_common.redis.redis_worker_tracker import RedisWorkerTracker


async def get_all_worker_ips() -> dict[str, WorkerIPData]:
    """
    Returns:
    {
        hostname: WorkerIPData
    }
    """
    tracker = RedisWorkerTracker(async_redis_client)
    raw_ips = await tracker.get_worker_ips_raw()

    result: dict[str, WorkerIPData] = {}

    for hostname, raw_value in raw_ips.items():
        try:
            ip_data = json.loads(raw_value)
            result[hostname] = WorkerIPData(
                ip=ip_data.get("ip", "unknown"),
                last_updated=ip_data.get("last_updated", 0)
            )
        except Exception:
            result[hostname] = WorkerIPData(
                ip=raw_value,
                last_updated=0
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


def register_periodic_update_worker_ip_task(lifespan_scope_tasks: list):
    """
    Registers periodic_update_worker_ip_task to run in background.
    """
    stop_event = asyncio.Event()
    task = asyncio.create_task(periodic_update_worker_ip_task(stop_event))
    lifespan_scope_tasks.append((task, stop_event))