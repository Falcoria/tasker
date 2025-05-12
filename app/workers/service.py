from typing import List, Dict

from app.redis_client import redis_client
from app.constants.redis_keys import WORKER_IP_KEY


def get_all_worker_ips() -> Dict[str, str]:
    """
    Fetch all registered worker IPs from Redis.
    Returns a dictionary: {hostname: ip}
    """
    return {k.decode(): v.decode() for k, v in redis_client.hgetall(WORKER_IP_KEY).items()}
