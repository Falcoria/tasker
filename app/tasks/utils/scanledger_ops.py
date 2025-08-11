from app.connectors.scanledger_connector import scanledger_connector
from app.logger import logger

from falcoria_common.schemas.enums.common import ImportMode


async def get_known_targets(project_id: str) -> set:
    try:
        records = await scanledger_connector.get_ips(project_id, has_ports=False)
        return {item.get("ip") for item in records if item.get("ip")}
    except Exception as e:
        logger.error(f"Error retrieving known IPs from ScanLedger: {e}")
        return set()


async def send_merge_hostnames(project_id: str, ips_to_merge: dict):
    if not ips_to_merge:
        return

    body = [{"ip": ip, "hostnames": target.hostnames, "ports": []} for ip, target in ips_to_merge.items()]
    logger.info(f"Sending merge request for {len(body)} IPs")

    try:
        await scanledger_connector.post_ips(
            project_id=project_id,
            body=body,
            query={"mode": ImportMode.INSERT.value}
        )
    except Exception as e:
        logger.error(f"Failed to send merge request: {e}")