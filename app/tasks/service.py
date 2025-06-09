import asyncio
import socket
from ipaddress import ip_address, IPv4Address, ip_network
from typing import List

from .schemas import NmapTask, RunNmapWithProject, ImportMode
from .redis_tracker import RedisTaskTracker

from app.logger import logger
from app.config import config
from app.connectors.scanledger_connector import scanledger_connector
from app.celery_app import send_scan, send_cancel, celery_app


from ipaddress import ip_network, ip_address, IPv4Address
import asyncio
import socket

# Define known private ranges per RFC1918
PRIVATE_RANGES = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]


def cidr_contains_private(cidr: str) -> bool:
    try:
        network = ip_network(cidr, strict=False)
        return any(network.overlaps(private_range) for private_range in PRIVATE_RANGES)
    except ValueError:
        return False


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


def expand_cidr(cidr: str) -> list[str]:
    try:
        network = ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]  # hosts(), not all addresses (skip network/broadcast)
    except ValueError:
        return []


async def validate_ips_and_hostnames(entries: list[str]) -> dict:
    results = {}
    semaphore = asyncio.Semaphore(config.optimal_semaphore)

    async def validate(entry: str):
        async with semaphore:
            if "/" in entry:
                expanded_ips = expand_cidr(entry)
                logger.debug(f"Expanded CIDR {entry} to {len(expanded_ips)} IPs.")

                if cidr_contains_private(entry):
                    logger.debug(f"CIDR {entry} contains private addresses.")
                    for ip in expanded_ips:
                        results[ip] = False
                else:
                    for ip in expanded_ips:
                        results[ip] = is_public_ip(ip)
            elif is_public_ip(entry):
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
        records = await scanledger_connector.get_ips(project_id, has_ports=False)
        result = set()
        for item in records:
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


async def get_targets_to_scan(project_id: str, mode: ImportMode, candidates: list[str], redis_tracker: RedisTaskTracker) -> list[str]:
    """
    Return only IPs/hostnames that are not in ScanLedger or in Redis,
    respecting INSERT mode deduplication.
    """
    if mode != ImportMode.INSERT:
        return candidates

    known_targets = await get_known_targets_from_scanledger(project_id)
    queued_targets = await redis_tracker.get_targets()

    targets_to_exclude = known_targets.union(queued_targets)
    target_to_include = [target for target in candidates if target not in targets_to_exclude]

    logger.info(f"Targets to scan for project {project_id} (after deduplication): {target_to_include}")
    return target_to_include


async def prepare_targets(targets: list[str]) -> tuple[list[str], list[str], dict[str, bool]]:
    deduplicated_targets = remove_duplicates(targets)
    validated_targets = await validate_ips_and_hostnames(deduplicated_targets)

    valid_targets = []
    invalid_targets = []
    all_targets = {}

    for target, is_valid in validated_targets.items():
        all_targets[target] = False  # Initialize all targets as "not scanned"
        if is_valid:
            valid_targets.append(target)
        else:
            invalid_targets.append(target)

    return valid_targets, invalid_targets, all_targets


def filter_allowed_targets(targets_to_scan: list[str]) -> list[str]:
    """
    If allowed_hosts is set in config, filter targets to only allowed ones.
    """
    # Later instead of config.allowed_hosts, we can use a more complex configuration
    # like scope from the scanledger.
    allowed_hosts = config.allowed_hosts_list

    if not allowed_hosts:
        return targets_to_scan

    allowed_set = set(allowed_hosts)
    allowed_targets = [t for t in targets_to_scan if t in allowed_set]
    disallowed_targets = [t for t in targets_to_scan if t not in allowed_set]

    for t in disallowed_targets:
        logger.warning(f"Target '{t}' is not allowed by allowed_hosts restriction — skipping.")

    return allowed_targets




async def send_nmap_task_for_target(
    target: str,
    nmap_scan_request: RunNmapWithProject,
    redis_tracker: RedisTaskTracker
) -> str:
    """Send a single Nmap task and track it in Redis."""
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

    task_id = send_scan(task)
    await redis_tracker.track_ip_task(target, task_id)
    return task_id


async def send_nmap_tasks(
    nmap_scan_request: RunNmapWithProject,
) -> dict[str, bool]:
    """Send Nmap tasks to RabbitMQ and track task IDs in Redis."""
    valid_targets, invalid_targets, all_targets = await prepare_targets(nmap_scan_request.hosts)

    if not valid_targets:
        logger.warning("No valid IPs or hostnames found.")
        return all_targets

    redis_tracker = RedisTaskTracker(nmap_scan_request.project_id)

    targets_to_scan = await get_targets_to_scan(
        nmap_scan_request.project_id,
        nmap_scan_request.mode,
        valid_targets,
        redis_tracker
    )

    if not targets_to_scan:
        logger.warning(f"No insertable IPs remaining after deduplication for project {nmap_scan_request.project_id}")
        return all_targets

    allowed_targets = filter_allowed_targets(targets_to_scan)

    semaphore = asyncio.Semaphore(config.optimal_semaphore)

    async def send_and_track_target(target: str):
        async with semaphore:
            lock_acquired = await redis_tracker.acquire_ip_lock(target, ttl_seconds=nmap_scan_request.timeout + 10)

            if not lock_acquired:
                logger.warning(f"Lock already present for {target} in project '{nmap_scan_request.project_id}' → skipping.")
                all_targets[target] = False
                return

            try:
                task_id = await send_nmap_task_for_target(target, nmap_scan_request, redis_tracker)
                all_targets[target] = True
                logger.info(f"Task sent for {target} in project '{nmap_scan_request.project_id}' with ID {task_id}")
            except Exception as e:
                logger.error(f"Error sending task for {target}: {e}")
                await redis_tracker.release_ip_lock(target)
                all_targets[target] = False

    await asyncio.gather(*(send_and_track_target(target) for target in allowed_targets))

    return all_targets


async def revoke_tasks(ip_task_pairs: List[tuple[str, str]], project_id: str) -> bool:
    """Revoke tasks by IP → task_id pairs concurrently."""
    redis_tracker = RedisTaskTracker(project_id)
    semaphore = asyncio.Semaphore(config.optimal_semaphore)

    async def revoke(ip: str, tid: str):
        async with semaphore:
            try:
                celery_app.control.revoke(tid, terminate=False)
                logger.info(f"Task {tid} revoked for IP {ip}.")

                await redis_tracker.remove_ip_task(ip)
                await redis_tracker.release_ip_lock(ip)
                logger.info(f"Removed IP {ip} and released lock in project {project_id}.")
            except Exception as e:
                logger.error(f"Failed to revoke task {tid} for IP {ip}: {e}")

    # Run all revokes concurrently
    await asyncio.gather(*(revoke(ip, tid) for ip, tid in ip_task_pairs))

    return True


async def revoke_project_tasks(
    project_id: str
) -> dict[str, bool]:
    """Revoke tasks for a given project and user."""
    redis_tracker = RedisTaskTracker(project_id)
    ip_task_map = await redis_tracker.get_ip_task_map()

    if not ip_task_map:
        logger.warning(f"No tasks found for project {project_id}.")
        return {"status": "no_tasks"}

    # Build explicit IP → task_id pairs
    ip_task_pairs = [
        (ip.decode() if isinstance(ip, bytes) else ip,
         tid.decode() if isinstance(tid, bytes) else tid)
        for ip, tid in ip_task_map.items()
    ]

    await revoke_tasks(ip_task_pairs, project_id)

    logger.info(f"Revoked tasks and sent cancel signal for project {project_id}.")
    send_cancel(project_id)

    return {"status": "ok"}


async def get_project_task_summary(project_id: str) -> dict[str, int]:
    """Get summary of project tasks based on Redis tracking."""
    redis_tracker = RedisTaskTracker(project_id)
    try:
        ip_task_map = await redis_tracker.get_ip_task_map()
        count = len(ip_task_map) if ip_task_map else 0
        return {
            "active_or_queued": count
        }
    except Exception as e:
        logger.error(f"Failed to get project task summary: {e}")
        return {"active_or_queued": 0}

