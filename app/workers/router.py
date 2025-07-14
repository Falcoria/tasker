from fastapi import APIRouter
from app.workers.service import get_all_worker_ips

workers_router = APIRouter(tags=["workers"])


@workers_router.get("/ips")
async def get_ips():
    """
    Get the list of IPs from the workers.
    """
    workers = await get_all_worker_ips()
    return {
        "workers": workers
    }