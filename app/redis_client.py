from app.config import config
from falcoria_common.redis.redis_client import FalcoriaRedisClient


async_redis_client = FalcoriaRedisClient.create_async_redis(
    host=config.redis_host,
    port=config.redis_port,
    db=config.redis_db,
    password=config.redis_password
)