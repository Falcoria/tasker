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
        # For /32 networks (single IPs), return the IP itself
        if network.num_addresses == 1:
            return [str(network.network_address)]
        # For larger networks, return all host IPs
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


async def fast_resolve_hostname(hostname: str, single_resolve: bool) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        results = await loop.getaddrinfo(
            hostname,
            None,
            family=socket.AF_INET,
            proto=socket.IPPROTO_TCP
        )
        ips = [res[4][0] for res in results]
        return [ips[0]] if single_resolve and ips else ips
    except Exception:
        return []


async def resolve_and_check_public(hostname: str, single_resolve: bool) -> list[str]:
    try:
        ips = await asyncio.wait_for(fast_resolve_hostname(hostname, single_resolve=single_resolve), timeout=2.0)
        return [ip for ip in ips if is_public_ip(ip)]
    except (asyncio.TimeoutError, Exception):
        return []


def remove_duplicates(entries: list[str]) -> list[str]:
    """
    Remove duplicates from a list of targets, normalizing IP addresses
    and CIDR blocks before comparison.
    """
    seen = set()
    result = []
    
    for entry in entries:
        # Normalize the entry for comparison
        if "/" in entry:
            # Handle CIDR notation - expand_cidr now handles /32 properly
            normalized_list = expand_cidr(entry)
            normalized = normalized_list[0] if normalized_list else entry
        else:
            # Try to normalize as an IP address
            try:
                ip_obj = ip_address(entry)
                normalized = str(ip_obj)
            except ValueError:
                # Not a valid IP, probably a hostname - return as-is
                normalized = entry
        
        if normalized not in seen:
            seen.add(normalized)
            result.append(entry)  # Keep original format in result
    
    return result