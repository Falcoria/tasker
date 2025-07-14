import asyncio

from app.logger import logger
from app.config import config
from app.tasks.schemas import (
    PreparedTarget, TargetDeclineReason, RunNmapWithProject, RefusedCounts,
    ScanStartSummary, ScanStartResponse, RevokeResponse, ProjectTaskSummary
)
from app.tasks.redis_tracker import AsyncRedisTaskTracker
from app.tasks.utils.target_processing import (
    is_public_ip, expand_cidr, resolve_and_check_public, remove_duplicates
)
from app.tasks.utils.scan_helpers import mark_unresolvable, update_target_reasons, collect_ips_to_merge
from app.tasks.utils.scanledger_ops import get_known_targets, send_merge_hostnames
from app.celery_app import send_scan, send_cancel, celery_app
from app.admin.schemas import UserOut
from app.admin.models import UserDB, ProjectDB

from .schemas import ImportMode, PreparedTarget, RunNmapRequest

from falcoria_common.schemas.nmap import TaskUser, NmapTask, RunningNmapTarget


async def resolve_targets(entries: list[str]) -> dict:
    prepared = {}
    sem = asyncio.Semaphore(config.dns_resolve_semaphore_limit)

    async def resolve_entry(entry: str):
        async with sem:
            if "/" in entry:
                for ip in expand_cidr(entry):
                    if is_public_ip(ip):
                        prepared.setdefault(ip, PreparedTarget(hostnames=[], valid=True))
            elif is_public_ip(entry):
                prepared[entry] = PreparedTarget(hostnames=[], valid=True)
            else:
                for _ in range(3):
                    ips = await resolve_and_check_public(entry)
                    if ips:
                        for ip in ips:
                            target = prepared.setdefault(ip, PreparedTarget(hostnames=[], valid=True))
                            target.hostnames.append(entry)
                        return
                    await asyncio.sleep(1)
                prepared[entry] = mark_unresolvable(entry)

    await asyncio.gather(*(resolve_entry(e) for e in entries))
    return prepared


async def process_scan_targets(
    project_id: str,
    mode: ImportMode,
    targets: dict,
    redis_tracker: AsyncRedisTaskTracker
) -> dict:
    if mode != mode.INSERT:
        return targets

    known = await get_known_targets(project_id)
    queued = await redis_tracker.get_targets()

    update_target_reasons(targets, known, queued)
    ips_to_merge = collect_ips_to_merge(targets)

    if ips_to_merge:
        await send_merge_hostnames(project_id, ips_to_merge)

    valid_ips = [ip for ip, t in targets.items() if t.valid]
    logger.info(f"Valid targets after deduplication: {valid_ips}")

    return targets


def filter_allowed_targets(prepared_targets: dict[str, PreparedTarget]) -> None:
    allowed = set(config.allowed_hosts_list or [])
    if not allowed:
        return

    for ip, target in prepared_targets.items():
        if target.valid and ip not in allowed:
            target.valid = False
            target.reason = TargetDeclineReason.FORBIDDEN
            logger.warning(f"Target {ip} forbidden by allowed_hosts restriction.")


async def prepare_scan_targets(nmap_scan_request: RunNmapWithProject) -> tuple:
    deduped = remove_duplicates(nmap_scan_request.hosts)
    prepared = await resolve_targets(deduped)
    tracker = AsyncRedisTaskTracker(nmap_scan_request.project_id)

    prepared = await process_scan_targets(nmap_scan_request.project_id, nmap_scan_request.mode, prepared, tracker)
    filter_allowed_targets(prepared)

    summary = ScanStartSummary(
        provided=len(nmap_scan_request.hosts),
        duplicates_removed=len(nmap_scan_request.hosts) - len(deduped),
        resolved_ips=len(prepared),
        refused=RefusedCounts(),
        sent_to_scan=0
    )

    for target in prepared.values():
        if not target.valid and target.reason:
            reason_key = target.reason.value
            setattr(summary.refused, reason_key, getattr(summary.refused, reason_key, 0) + 1)

    return prepared, summary, tracker


async def send_single_nmap_task(target_ip: str, target: PreparedTarget, req: RunNmapWithProject, tracker: AsyncRedisTaskTracker) -> str:
    open_ports_str = " ".join(str(p) for p in req.open_ports_opts.ports)
    open_ports_opts = " ".join(req.open_ports_opts.to_nmap_args())
    req.service_opts._transport_protocol = req.open_ports_opts.transport_protocol
    service_opts = " ".join(req.service_opts.to_nmap_args())
    user = req.user.model_dump()
    task_user = TaskUser(**user)

    task = NmapTask(
        ip=target_ip,
        hostnames=target.hostnames,
        project=req.project_id,
        open_ports_opts=open_ports_opts,
        service_opts=service_opts,
        timeout=req.timeout,
        include_services=req.include_services,
        mode=req.mode,
        user=task_user,
        open_ports_str=open_ports_str
    )

    task_id = send_scan(task)
    await tracker.track_nmap_task(
        task_id=task_id, 
        project_id=req.project_id, 
        user_id=str(task_user.id), 
        ip=target_ip, 
        ports=open_ports_str
    )
    return task_id


async def process_insert_mode_targets(prepared: dict, req: RunNmapWithProject, tracker: AsyncRedisTaskTracker, summary: ScanStartSummary) -> dict:
    locked_ips = await tracker.get_locked_ips(req.project_id)
    result = {}
    for ip, target in prepared.items():
        if not target.valid:
            continue
        if ip in locked_ips:
            target.valid = False
            target.reason = TargetDeclineReason.ALREADY_IN_QUEUE
            summary.refused.already_in_queue += 1
        else:
            result[ip] = target
    return result


async def send_single_target(ip: str, target: PreparedTarget, req: RunNmapWithProject, tracker: AsyncRedisTaskTracker, summary: ScanStartSummary, sem: asyncio.Semaphore, port_string: str):
    async with sem:
        try:
            if not await tracker.acquire_lock_ip_ports(req.project_id, ip, port_string, ttl_seconds=req.timeout + 10):
                target.valid = False
                target.reason = TargetDeclineReason.ALREADY_IN_QUEUE
                summary.refused.already_in_queue += 1
                return
            task_id = await send_single_nmap_task(ip, target, req, tracker)
            summary.sent_to_scan += 1
            logger.info(f"Task {task_id} sent for {ip}")
        except Exception as e:
            await tracker.release_lock_ip_ports(req.project_id, ip, port_string)
            target.valid = False
            target.reason = TargetDeclineReason.OTHER
            summary.refused.other += 1
            logger.error(f"Error sending task for {ip}: {e}")


async def send_scan_tasks(prepared: dict, req: RunNmapWithProject, tracker: AsyncRedisTaskTracker, summary: ScanStartSummary) -> ScanStartSummary:
    sem = asyncio.Semaphore(config.optimal_semaphore)
    port_string = " ".join(str(p) for p in req.open_ports_opts.ports)

    if req.mode == ImportMode.INSERT:
        prepared = await process_insert_mode_targets(prepared, req, tracker, summary)

    await asyncio.gather(*(
        send_single_target(ip, target, req, tracker, summary, sem, port_string)
        for ip, target in prepared.items() if target.valid
    ))

    return summary


async def send_nmap_tasks(
    nmap_scan_request: RunNmapRequest,
    project: ProjectDB,
    user: UserDB
) -> ScanStartResponse:
    nmap_scan_request = RunNmapWithProject(
        **nmap_scan_request.model_dump(),
        project_id=str(project.id),
        user=UserOut.model_validate(user.model_dump())
    )

    prepared, summary, tracker = await prepare_scan_targets(nmap_scan_request)
    summary = await send_scan_tasks(prepared, nmap_scan_request, tracker, summary)
    return ScanStartResponse(summary=summary, prepared_targets=prepared)


async def revoke_tasks(task_ids: list[str], project_id: str) -> int:
    tracker = AsyncRedisTaskTracker(project_id)
    sem = asyncio.Semaphore(config.optimal_semaphore)
    count = 0

    async def revoke(tid: str):
        nonlocal count
        async with sem:
            try:
                celery_app.control.revoke(tid, terminate=False)
                metadata = await tracker.get_task_metadata(tid)
                if not metadata:
                    logger.warning(f"No metadata for task {tid}")
                    return

                await tracker.cleanup_task_metadata(
                    task_id=tid,
                    project_id=project_id,
                    ip=metadata.ip,
                    port_string=metadata.ports
                )
                count += 1
                logger.info(f"Revoked task {tid} for {metadata.ip}")
            except Exception as e:
                logger.error(f"Failed to revoke task {tid}: {e}")

    await asyncio.gather(*(revoke(tid) for tid in task_ids))
    return count


async def revoke_project_tasks(project_id: str) -> RevokeResponse:
    tracker = AsyncRedisTaskTracker(project_id)
    task_ids = await tracker.get_queued_tasks(project_id)

    # 1. revoke the tasks for the project
    # 2. send cancel with task_ids
    # 3. clean up entries in Redis
    # 4. clean up locks

    if not task_ids:
        return RevokeResponse(status="no_tasks", revoked=0)

    revoked = await revoke_tasks(task_ids, project_id)
    send_cancel(task_ids)
    return RevokeResponse(status="stopped", revoked=revoked)


async def get_running_targets(project_id: str) -> list[RunningNmapTarget]:
    tracker = AsyncRedisTaskTracker(project_id)
    try:
        raw = await tracker.get_running_targets_raw()
        return [RunningNmapTarget(**d) for d in raw]
    except Exception as e:
        logger.error(f"Failed to get running targets: {e}")
        return []


async def get_scan_status(project_id: str) -> ProjectTaskSummary:
    tracker = AsyncRedisTaskTracker(project_id)
    try:
        ip_task_map = await tracker.get_queued_tasks(project_id)
        running = await get_running_targets(project_id)
        return ProjectTaskSummary(
            active_or_queued=len(ip_task_map) if ip_task_map else 0,
            running= len(running),
            running_targets=running
        )
    except Exception as e:
        logger.error(f"Failed to get scan status: {e}")
        return ProjectTaskSummary(active_or_queued=0, running=0, running_targets=[])
