from app.tasks.schemas import PreparedTarget, TargetDeclineReason
from app.logger import logger

def mark_unresolvable(entry: str) -> PreparedTarget:
    logger.warning(f"Giving up on hostname {entry} after retries.")
    return PreparedTarget(
        hostnames=[entry],
        valid=False,
        reason=TargetDeclineReason.UNRESOLVABLE
    )

def update_target_reasons(prepared_targets: dict, known_targets: set, queued_targets: set):
    for ip, target in prepared_targets.items():
        if target.valid and ip in known_targets:
            target.valid = False
            target.reason = TargetDeclineReason.ALREADY_IN_SCANLEDGER
        elif target.valid and ip in queued_targets:
            target.valid = False
            target.reason = TargetDeclineReason.ALREADY_IN_QUEUE

def collect_ips_to_merge(prepared_targets: dict) -> dict:
    return {
        ip: target for ip, target in prepared_targets.items()
        if not target.valid and target.reason == TargetDeclineReason.ALREADY_IN_SCANLEDGER and target.hostnames
    }