import asyncio
import socket
from ipaddress import ip_address, IPv4Address
from typing import List

from .schemas import NmapTask, RunNmapWithProject, ImportMode
from .redis_tracker import (
    track_task_id, 
    get_task_ids, 
    remove_task_id, 
    track_ip_task, 
    get_ip_task_map, 
    remove_ip_task
)

from app.logger import logger
from app.config import config
from app.connectors.scanledger_connector import scanledger_connector
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


async def get_known_targets_from_scanledger(project_id: str) -> set[str]:
    """
    Return a combined set of all known IPs and hostnames from ScanLedger.
    """
    try:
        entries = await scanledger_connector.get_ips(project_id, has_ports=False)
        result = set()
        for item in entries:
            ip = item.get("ip")
            if ip:
                result.add(ip)
            hostnames = item.get("hostnames", [])
            if hostnames:
                result.update(hostnames)
        logger.info(f"Targets from ScanLedger for project {project_id}: {result}")
        return result
    except Exception as e:
        logger.error(f"Error retrieving known targets from ScanLedger for project {project_id}: {e}")
        return set()


async def get_targets_from_redis(project_id: str) -> set[str]:
    """
    Get IPs from Redis (currently queued) as a set.
    Decodes bytes to strings.
    """
    try:
        ip_task_map = await get_ip_task_map(project_id)
        if not ip_task_map:
            logger.warning(f"No IPs found in Redis for project {project_id}.")
            return set()

        ips = {k.decode() if isinstance(k, bytes) else k for k in ip_task_map.keys()}
        logger.info(f"Targets in Redis for project {project_id}: {ips}")
        return ips

    except Exception as e:
        logger.error(f"Error retrieving targets from Redis for project {project_id}: {e}")
        return set()


async def get_insertable_ips(project_id: str, mode: ImportMode, candidates: list[str]) -> list[str]:
    """
    Return only IPs/hostnames that are not in ScanLedger or in Redis,
    respecting INSERT mode deduplication.
    """
    if mode != ImportMode.INSERT:
        return candidates

    known_targets = await get_known_targets_from_scanledger(project_id)
    queued_targets = await get_targets_from_redis(project_id)

    all_excluded = known_targets.union(queued_targets)
    filtered = [ip for ip in candidates if ip not in all_excluded]
    logger.info(f"Insert-mode filtered targets for project {project_id}: {filtered}")
    return filtered


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

    # Filter out duplicates in insert mode
    filtered_targets = await get_insertable_ips(
        nmap_scan_request.project_id,
        nmap_scan_request.mode,
        valid_targets
    )

    if not filtered_targets:
        logger.warning(f"No insertable IPs remaining after deduplication for project {nmap_scan_request.project_id}")

    # Initialize final results with all valid targets as False (not sent)
    final_results = {target: False for target in valid_targets}

    for target in filtered_targets:
        open_ports_opts = " ".join(nmap_scan_request.open_ports_opts.to_nmap_args())
        nmap_scan_request.service_opts._transport_protocol = nmap_scan_request.open_ports_opts.transport_protocol
        service_opts = " ".join(nmap_scan_request.service_opts.to_nmap_args())

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
            await track_ip_task(nmap_scan_request.project_id, target, task_id)
            logger.info(f"Task sent for {target} in project '{nmap_scan_request.project_id}' with ID {task_id}")
            final_results[target] = True
        except Exception as e:
            logger.error(f"Error sending task for {target}: {e}")
            continue

    return final_results


async def revoke_tasks(task_ids: List[str | bytes], project_id: str) -> bool:
    """Revoke a task by its ID."""
    for tid in task_ids:
        tid = tid.decode() if isinstance(tid, bytes) else tid
        try:
            celery_app.control.revoke(tid, terminate=False)
            logger.info(f"Task {tid} revoked.")

            await remove_task_id(project_id, tid)
            await remove_ip_task(project_id, tid)
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
