from fastapi import FastAPI, Depends

from app.config import config
from app.tasks.router import tasks_router
from app.workers.router import workers_router


def create_app():
    fastapi_app = FastAPI(
        #docs_url=config.docs_url, 
        #redoc_url=config.redoc_url,
    )
    fastapi_app.include_router(tasks_router, prefix="/tasks")
    fastapi_app.include_router(workers_router, prefix="/workers")
    return fastapi_app