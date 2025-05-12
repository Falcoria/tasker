from celery import Celery
from kombu import Exchange, Queue

from app.config import config
from app.tasks.schemas import NmapTask
from app.tasks.schemas import TaskNames


celery_app = Celery(config.celery_app_name, broker=config.rabbitmq_url)
nmap_exchange = Exchange(config.nmap_exchange_name, type=config.exchange_type)

celery_app.conf.update(
    task_queues=[
        Queue(config.nmap_scan_queue_name, exchange=nmap_exchange, routing_key=config.nmap_scan_routing_key),
        Queue(config.nmap_cancel_queue_name, exchange=nmap_exchange, routing_key=config.nmap_cancel_routing_key),
    ],
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
)


def send_scan(nmap_task: NmapTask) -> str:
    """Send a scan task to the Celery worker."""  
    result = celery_app.send_task(
        name=TaskNames.PROJECT_SCAN,
        args=[nmap_task.model_dump()],
        exchange=nmap_exchange.name,
        routing_key=config.nmap_scan_routing_key
    )
    return result.id


def send_cancel(project: str) -> str:
    """Send a cancel task to the Celery worker."""
    result = celery_app.send_task(
        name=TaskNames.PROJECT_CANCEL,
        args=[str(project)],
        exchange=nmap_exchange.name,
        routing_key=config.nmap_cancel_routing_key
    )
    return result.id