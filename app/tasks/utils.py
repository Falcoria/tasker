import socket

import aiofiles
import aiofiles.os
import aiodns

from app.logger import logger


resolver = aiodns.DNSResolver()

async def fast_resolve_hostname(hostname: str) -> list[str]:
    try:
        result = await resolver.gethostbyname(hostname, socket.AF_INET)
        return result.addresses
    except Exception:
        return []


async def delete_file(filepath: str):
    """ Deletes the file at the given path."""
    try:
        await aiofiles.os.remove(filepath)
        return True
    except Exception as e:
        logger.error(f"Exception: delete_file {e}")
        return False


async def read_and_decode_file(filepath: str) -> str:
    """ Reads, decodes and deletes the file at the given"""
    content = None
    try:
        async with aiofiles.open(filepath, 'r') as f:
            content = await f.read()
    except Exception as e:
        logger.error(f"Exception. {e}")
    finally:
        await delete_file(filepath)
        return content