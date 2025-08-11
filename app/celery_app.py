from celery import Celery
from kombu import Exchange, Queue
from kombu.common import Broadcast

from app.config import config
from app.logger import logger
from falcoria_common.schemas.nmap import NmapTask
from falcoria_common.schemas.enums.celery_routes import NmapTasks, WorkerTasks


celery_app = Celery(config.celery_app_name, broker=config.rabbitmq_url)
nmap_exchange = Exchange(config.nmap_exchange_name, type=config.exchange_type)

celery_app.conf.update(
    task_queues=[
        Queue(config.nmap_scan_queue_name, exchange=nmap_exchange, routing_key=config.nmap_scan_routing_key),
        Broadcast(name=config.nmap_cancel_queue_name),
        Broadcast(name=config.worker_service_broadcast_queue),
    ],
    task_routes = {
        NmapTasks.NMAP_SCAN: {
            'queue': config.nmap_scan_queue_name,
        },
        NmapTasks.NMAP_CANCEL: {
            'queue': config.nmap_cancel_queue_name,
        },
        WorkerTasks.UPDATE_WORKER_IP: {
            'queue': config.worker_service_broadcast_queue,
        }
    },
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
)


def send_scan(nmap_task: NmapTask) -> str:
    """Send a scan task to the Celery worker."""  
    result = celery_app.send_task(
        name=NmapTasks.NMAP_SCAN,
        args=[nmap_task.model_dump()],
        exchange=nmap_exchange.name,
        routing_key=config.nmap_scan_routing_key
    )
    return result.id


def send_cancel(task_ids: list[str]) -> str:
    """Broadcast cancel task to all workers."""
    logger.info(f"Broadcasting cancel task for project")
    result = celery_app.send_task(
        name=NmapTasks.NMAP_CANCEL,
        args=[{'task_ids': task_ids}],
        queue=config.nmap_cancel_queue_name,
    )
    return result.id


def send_worker_service_task(task_name: str, *args) -> str:
    """Broadcast a service task to all workers."""
    logger.info(f"Broadcasting service task {task_name} with args {args}")
    result = celery_app.send_task(
        name=task_name,
        args=args,
        queue=config.worker_service_broadcast_queue,
    )
    return result.id