from app.redis_client import async_redis_client


async def track_task_id(project: str, task_id: str):
    await async_redis_client.rpush(f"project:{project}:task_ids", task_id)

async def get_task_ids(project: str):
    task_ids = await async_redis_client.lrange(f"project:{project}:task_ids", 0, -1)
    return task_ids

async def remove_task_id(project: str, task_id: str):
    await async_redis_client.lrem(f"project:{project}:task_ids", 0, task_id)
    return