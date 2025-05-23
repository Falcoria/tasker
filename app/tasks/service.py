import asyncio
import socket
from ipaddress import ip_address, IPv4Address
from typing import List

from .schemas import NmapTask, RunNmapWithProject
from .utils import read_and_decode_file
from .redis_tracker import track_task_id, get_task_ids, remove_task_id

from app.logger import logger
from app.config import config

from app.celery_app import send_scan, send_cancel, celery_app


def is_public_ip(ip: str) -> bool:
    """Check if the provided IP address is public"""
    try:
        ip_obj = ip_address(ip)
        return isinstance(ip_obj, IPv4Address) and not ip_obj.is_private
    except ValueError:
        return False


async def resolve_hostname(hostname: str) -> str:
    """Resolve the hostname asynchronously with a timeout."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, socket.gethostbyname, hostname)

async def resolve_and_check_public(hostname: str) -> bool:
    """Resolve hostname and check if the resolved IP is public."""
    try:
        # Set a 2-second timeout for hostname resolution
        ip = await asyncio.wait_for(resolve_hostname(hostname), timeout=2.0)
        return is_public_ip(ip)
    except (asyncio.TimeoutError, socket.gaierror, ValueError):
        return False


async def validate_ips_and_hostnames(entries: list[str]) -> dict:
    """Validate a list of IP addresses and hostnames with concurrency limits."""
    results = {}
    semaphore = asyncio.Semaphore(config.optimal_semaphore)

    async def validate(entry: str):
        async with semaphore:  # Limit concurrent calls
            if is_public_ip(entry):
                results[entry] = True
            else:
                results[entry] = await resolve_and_check_public(entry)
                logger.debug(f"Resolved {entry} to {results[entry]}")

    await asyncio.gather(*(validate(entry) for entry in entries))
    return results


def remove_duplicates(entries: list[str]) -> list[str]:
    """Remove duplicates from a list of entries."""
    return list(set(entries))


async def send_nmap_tasks(
    nmap_scan_request: RunNmapWithProject,
) -> dict[str, bool] | None:
    """Send Nmap tasks to RabbitMQ and track task IDs in Redis."""
    targets = remove_duplicates(nmap_scan_request.hosts)
    validation_results = await validate_ips_and_hostnames(targets)

    valid_targets = [t for t, is_valid in validation_results.items() if is_valid]
    if not valid_targets:
        logger.warning("No valid IPs or hostnames found.")
        return None

    for target in valid_targets:
        open_ports_opts_list = nmap_scan_request.open_ports_opts.to_nmap_args()
        open_ports_opts = " ".join(open_ports_opts_list)
        service_opts_list = nmap_scan_request.service_opts.to_nmap_args()
        service_opts = " ".join(service_opts_list)
        
        task = NmapTask(
            ip=target,
            project=nmap_scan_request.project_id,
            open_ports_opts=open_ports_opts,
            service_opts=service_opts,
            timeout=nmap_scan_request.timeout,
            include_services=nmap_scan_request.include_services,
            mode=nmap_scan_request.mode,
        )
        try:
            task_id = send_scan(task)
            await track_task_id(nmap_scan_request.project_id, task_id)
            logger.info(f"Task sent for {target} in project '{nmap_scan_request.project_id}' with ID {task_id}")
        except Exception as e:
            logger.error(f"Error sending task for {target}: {e}")
            continue

    return validation_results


async def revoke_tasks(task_ids: List[str | bytes], project_id: str) -> bool:
    """Revoke a task by its ID."""
    for tid in task_ids:
        tid = tid.decode() if isinstance(tid, bytes) else tid
        try:
            celery_app.control.revoke(tid, terminate=False)
            logger.info(f"Task {tid} revoked.")

            await remove_task_id(project_id, tid)
            logger.info(f"Task ID {tid} removed from Redis.")
        except Exception as e:
            logger.error(f"Failed to revoke task {tid}: {e}")
            continue

        logger.info(f"Revoked task with ID {tid}")
    return True


async def revoke_project_tasks(
    project_id: str
) -> dict[str, bool]:
    """Revoke tasks for a given project and user."""
    task_ids = await get_task_ids(project_id)
    if not task_ids:
        logger.warning(f"No tasks found for project {project_id}.")
        return {"status": "no_tasks"}

    revoked = await revoke_tasks(task_ids, project_id)
    if revoked:
        logger.info(f"Revoked tasks for project {project_id}.")
    else:
        logger.warning(f"Failed to revoke tasks for project {project_id}.")

    send_cancel(project_id)
    logger.info(f"Sent cancel signal for project {project_id}.")
    return {"status": "ok"}


async def get_project_task_summary(project: str) -> dict[str, int]:
    """Get summary of project tasks based on Redis tracking."""
    try:
        task_ids = await get_task_ids(project)
        count = len(task_ids) if task_ids else 0
        return {
            "active_or_queued": count
        }
    except Exception as e:
        logger.error(f"Failed to get project task summary: {e}")
        return {"active_or_queued": 0}
