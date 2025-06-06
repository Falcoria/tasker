import json
import asyncio
from typing import Dict

from app.redis_client import redis_client
from app.constants.redis_keys import WORKER_IP_KEY
from app.celery_app import send_worker_service_task
from app.logger import logger
from app.config import config

from .schemas import TaskNames


def get_all_worker_ips() -> Dict[str, str]:
    """
    Fetch all registered worker IPs from Redis.
    Returns a dictionary:
    {
        hostname: {
            "ip": ip,
            "last_updated": timestamp
        }
    }
    """
    result = {}
    keys = redis_client.keys("worker_ip:*")

    for key in keys:
        hostname = key.decode().split(":", 1)[1]
        raw_value = redis_client.get(key)
        if raw_value:
            try:
                ip_data = json.loads(raw_value.decode())
                result[hostname] = {
                    "ip": ip_data.get("ip", "unknown"),
                    "last_updated": ip_data.get("last_updated", 0)
                }
            except Exception:
                result[hostname] = {
                    "ip": raw_value.decode(),
                    "last_updated": 0
                }

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
            await asyncio.wait_for(stop_event.wait(), timeout=config.worker_ip_update_ttl)  # 1 hour
        except asyncio.TimeoutError:
            pass  # normal wake-up


def register_periodic_update_worker_ip_task(lifespan_scope_tasks: list):
    """
    Registers periodic_update_worker_ip_task to run in background.
    App_lifespan will pass the list to collect background tasks.
    """
    stop_event = asyncio.Event()
    task = asyncio.create_task(periodic_update_worker_ip_task(stop_event))

    # Append a (task, stop_event) tuple to the list so the main lifespan can handle it
    lifespan_scope_tasks.append((task, stop_event))