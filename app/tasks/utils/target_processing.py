import asyncio
import socket
from ipaddress import ip_network, ip_address, IPv4Address

import aiodns


resolver = aiodns.DNSResolver()

def is_public_ip(ip: str) -> bool:
    try:
        ip_obj = ip_address(ip)
        return isinstance(ip_obj, IPv4Address) and not ip_obj.is_private
    except ValueError:
        return False


def expand_cidr(cidr: str) -> list[str]:
    try:
        network = ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


async def fast_resolve_hostname(hostname: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        return [res[4][0] for res in await loop.getaddrinfo(hostname, None, family=socket.AF_INET, proto=socket.IPPROTO_TCP)]
    except Exception:
        return []


async def resolve_and_check_public(hostname: str) -> list[str]:
    try:
        ips = await asyncio.wait_for(fast_resolve_hostname(hostname), timeout=2.0)
        return [ip for ip in ips if is_public_ip(ip)]
    except (asyncio.TimeoutError, Exception):
        return []


def remove_duplicates(entries: list[str]) -> list[str]:
    return list(set(entries))