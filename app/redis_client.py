from redis import StrictRedis
from redis.asyncio import Redis

from app.config import config


redis_client = StrictRedis(
    host=config.redis_host,
    port=config.redis_port,
    db=config.redis_db,
    password=config.redis_password
)

async_redis_client = Redis(
    host=config.redis_host,
    port=config.redis_port,
    db=config.redis_db,
    password=config.redis_password
)