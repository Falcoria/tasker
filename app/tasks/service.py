import asyncio
import socket
from ipaddress import ip_address, IPv4Address, ip_network
from typing import List

from .schemas import NmapTask, RunNmapWithProject, ImportMode, PreparedTarget, TargetDeclineReason
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
    """Check if the provided CIDR contains any private IP addresses."""
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


async def resolve_hostname(hostname: str) -> list[str]:
    """Resolve hostname to a list of IPv4 addresses only."""
    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
        ip_list = [item[4][0] for item in addr_info if item[0] == socket.AF_INET]  # IPv4 only
        return list(set(ip_list))
    except socket.gaierror as e:
        logger.warning(f"Error resolving hostname {hostname}: {e}")
        return []


async def resolve_and_check_public(hostname: str) -> bool:
    """Resolve hostname and check if all resolved IPv4 IPs are public."""
    try:
        # Set a 2-second timeout for hostname resolution
        ips = await asyncio.wait_for(resolve_hostname(hostname), timeout=2.0)
        if not ips:
            return False

        # All IPs must be public → use all()
        return all(is_public_ip(ip) for ip in ips)

    except (asyncio.TimeoutError, socket.gaierror, ValueError):
        return False


def expand_cidr(cidr: str) -> list[str]:
    try:
        network = ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]  # hosts(), not all addresses (skip network/broadcast)
    except ValueError:
        return []


async def resolve_targets_to_prepared_targets(entries: list[str]) -> dict[str, PreparedTarget]:
    ip_to_prepared_target: dict[str, PreparedTarget] = {}
    semaphore = asyncio.Semaphore(config.optimal_semaphore)

    async def process_cidr(entry: str):
        expanded_ips = expand_cidr(entry)
        for ip in expanded_ips:
            if is_public_ip(ip):
                ip_to_prepared_target[ip] = PreparedTarget(
                    hostnames=[ip],  # treat IP as self-hostname
                    valid=True
                )

    async def process_ip(entry: str):
        ip_to_prepared_target[entry] = PreparedTarget(
            hostnames=[entry],
            valid=True
        )

    async def process_hostname(entry: str):
        max_attempts = 3

        for attempt in range(1, max_attempts + 1):
            try:
                resolved_ips = await asyncio.wait_for(resolve_hostname(entry), timeout=2.0)
                logger.info(f"Resolved hostname {entry} (attempt {attempt}) → {resolved_ips}")

                public_ips = [ip for ip in resolved_ips if is_public_ip(ip)]
                if public_ips:
                    for ip in public_ips:
                        target = ip_to_prepared_target.get(ip)
                        if not target:
                            target = PreparedTarget(
                                hostnames=[],
                                valid=True
                            )
                            ip_to_prepared_target[ip] = target

                        target.hostnames.append(entry)
                    return  # success → stop attempts

                else:
                    logger.warning(f"Hostname {entry} resolved to no public IPs (attempt {attempt}). Retrying...")

            except Exception as e:
                await asyncio.sleep(1)  # Wait before retrying
                logger.warning(f"Failed to resolve hostname {entry} (attempt {attempt}): {e}")

        # All attempts failed → fallback
        ip_to_prepared_target[entry] = PreparedTarget(
            hostnames=[entry],
            valid=False,
            reason=TargetDeclineReason.UNRESOLVABLE
        )
        logger.warning(f"Giving up on hostname {entry} after {max_attempts} attempts.")

    async def resolve(entry: str):
        async with semaphore:
            if "/" in entry:
                await process_cidr(entry)
            elif is_public_ip(entry):
                await process_ip(entry)
            else:
                await process_hostname(entry)

    await asyncio.gather(*(resolve(entry) for entry in entries))
    return ip_to_prepared_target


def remove_duplicates(entries: list[str]) -> list[str]:
    """Remove duplicates from a list of entries."""
    return list(set(entries))


async def get_known_targets_from_scanledger(project_id: str) -> set[str]:
    """
    Return a set of known IPs from ScanLedger.
    """
    try:
        records = await scanledger_connector.get_ips(project_id, has_ports=False)
        known_ips = set()
        for item in records:
            ip = item.get("ip")
            if ip:
                known_ips.add(ip)

        return known_ips
    except Exception as e:
        logger.error(f"Error retrieving known IPs from ScanLedger for project {project_id}: {e}")
        return set()


async def send_merge_hostnames_to_scanledger(
    project_id: str,
    ips_to_merge: dict[str, PreparedTarget]
):
    """
    Send existing IPs to ScanLedger with hostnames only, using INSERT mode.
    """
    if not ips_to_merge:
        return  # Nothing to send

    body = []
    for ip, target in ips_to_merge.items():
        body.append({
            "ip": ip,
            "hostnames": target.hostnames,
            "ports": [],  # Required field → send empty
        })

    logger.info(f"Sending merge hostnames request for {len(body)} IPs to ScanLedger (INSERT mode)")

    try:
        await scanledger_connector.post_ips(
            project_id=project_id,
            body=body,
            query={"mode": ImportMode.INSERT.value}
        )
    except Exception as e:
        logger.error(f"Failed to send merge hostnames request: {e}")


async def get_targets_to_scan(
    project_id: str,
    mode: ImportMode,
    prepared_targets: dict[str, PreparedTarget],
    redis_tracker: RedisTaskTracker
) -> dict[str, PreparedTarget]:
    """
    Update PreparedTarget.valid and reason accordingly.
    Return the updated PreparedTargets dict.
    """

    if mode != ImportMode.INSERT:
        return prepared_targets  # No changes needed

    known_targets = await get_known_targets_from_scanledger(project_id)
    queued_targets = await redis_tracker.get_targets()

    _update_target_reasons(prepared_targets, known_targets, queued_targets)

    ips_to_merge = _collect_ips_to_merge(prepared_targets)

    if ips_to_merge:
        await send_merge_hostnames_to_scanledger(project_id, ips_to_merge)

    logger.info(
        f"Targets to scan for project {project_id} after deduplication: "
        f"{[ip for ip, target in prepared_targets.items() if target.valid]}"
    )

    return prepared_targets


def _get_valid_targets(prepared_targets: dict[str, PreparedTarget]) -> list[str]:
    return [
        ip for ip, target in prepared_targets.items()
        if target.valid
    ]


def _update_target_reasons(
    prepared_targets: dict[str, PreparedTarget],
    known_targets: set[str],
    queued_targets: set[str]
) -> None:
    for ip, target in prepared_targets.items():
        if target.valid and ip in known_targets:
            target.valid = False
            target.reason = TargetDeclineReason.ALREADY_IN_SCANLEDGER
        elif target.valid and ip in queued_targets:
            target.valid = False
            target.reason = TargetDeclineReason.ALREADY_IN_QUEUE


def _collect_ips_to_merge(prepared_targets: dict[str, PreparedTarget]) -> dict[str, PreparedTarget]:
    return {
        ip: target for ip, target in prepared_targets.items()
        if not target.valid
        and target.reason in {
            TargetDeclineReason.ALREADY_IN_SCANLEDGER
        }
        and target.hostnames
    }


def filter_allowed_targets(prepared_targets: dict[str, PreparedTarget]) -> None:
    """
    If allowed_hosts is set in config, update PreparedTarget.valid and reason accordingly.
    """
    allowed_hosts = config.allowed_hosts_list

    if not allowed_hosts:
        return  # No restriction — do nothing

    allowed_set = set(allowed_hosts)

    for ip, target in prepared_targets.items():
        if target.valid and ip not in allowed_set:
            target.valid = False
            target.reason = TargetDeclineReason.FORBIDDEN
            logger.warning(f"Target '{ip}' is not allowed by allowed_hosts restriction — marking as forbidden.")


async def send_nmap_task_for_target(
    target_ip: str,
    hostnames: list[str],
    nmap_scan_request: RunNmapWithProject,
    redis_tracker: RedisTaskTracker
) -> str:
    """Send a single Nmap task and track it in Redis."""
    open_ports_opts = " ".join(nmap_scan_request.open_ports_opts.to_nmap_args())
    nmap_scan_request.service_opts._transport_protocol = nmap_scan_request.open_ports_opts.transport_protocol
    service_opts = " ".join(nmap_scan_request.service_opts.to_nmap_args())

    task = NmapTask(
        ip=target_ip,
        hostnames=hostnames,
        project=nmap_scan_request.project_id,
        open_ports_opts=open_ports_opts,
        service_opts=service_opts,
        timeout=nmap_scan_request.timeout,
        include_services=nmap_scan_request.include_services,
        mode=nmap_scan_request.mode,
    )

    task_id = send_scan(task)
    await redis_tracker.track_ip_task(target_ip, task_id)
    return task_id


async def send_nmap_tasks(
    nmap_scan_request: RunNmapWithProject,
) -> dict[str, PreparedTarget]:
    """Send Nmap tasks to RabbitMQ and track task IDs in Redis. Return prepared_targets dict."""
    # Deduplicate input
    deduplicated_hosts = remove_duplicates(nmap_scan_request.hosts)
    prepared_targets = await resolve_targets_to_prepared_targets(deduplicated_hosts)

    redis_tracker = RedisTaskTracker(nmap_scan_request.project_id)

    # Update prepared_targets with ScanLedger/Redis checks
    prepared_targets = await get_targets_to_scan(
        nmap_scan_request.project_id,
        nmap_scan_request.mode,
        prepared_targets,
        redis_tracker
    )

    # Filter allowed targets → updates prepared_targets in-place
    filter_allowed_targets(prepared_targets)

    # Prepare list of IPs to scan (final pass)
    targets_to_scan = [
        ip for ip, target in prepared_targets.items()
        if target.valid
    ]

    if not targets_to_scan:
        logger.info(f"No targets to scan for project {nmap_scan_request.project_id}.")
        return prepared_targets
    else:
        logger.info(f"Sending Nmap tasks for {len(targets_to_scan)} targets in project {nmap_scan_request.project_id}: {targets_to_scan}")

    semaphore = asyncio.Semaphore(config.optimal_semaphore)

    async def send_and_track_target(target_ip: str, target: PreparedTarget):
        try:
            async with semaphore:
                lock_acquired = await redis_tracker.acquire_ip_lock(
                    target_ip, ttl_seconds=nmap_scan_request.timeout + 10
                )

                if not lock_acquired:
                    logger.warning(f"Lock already present for {target_ip} in project '{nmap_scan_request.project_id}' → skipping.")
                    target.valid = False
                    target.reason = TargetDeclineReason.ALREADY_IN_QUEUE
                    return

                try:
                    task_id = await send_nmap_task_for_target(target_ip, target.hostnames, nmap_scan_request, redis_tracker)
                    logger.info(f"Task sent for {target_ip} in project '{nmap_scan_request.project_id}' with ID {task_id}")
                except Exception as e:
                    logger.error(f"Error sending task for {target_ip}: {e}")
                    await redis_tracker.release_ip_lock(target_ip)
                    target.valid = False
                    target.reason = TargetDeclineReason.OTHER
        except Exception as e:
            logger.error(f"Unexpected error in send_and_track_target for {target_ip}: {e}")

    await asyncio.gather(
        *(
            send_and_track_target(ip, prepared_targets[ip])
            for ip in targets_to_scan
        )
    )

    # Now just return the full prepared_targets → raw dict
    return prepared_targets


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

