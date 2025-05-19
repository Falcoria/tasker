from fastapi import FastAPI

from app.config import config
from app.tasks.router import tasks_router
from app.workers.router import workers_router
from app.error_handlers import register_error_handlers

def create_app():
    fastapi_app = FastAPI(
        docs_url=config.docs_url, 
        redoc_url=config.redoc_url,
    )

    # Register error handlers
    register_error_handlers(fastapi_app)

    fastapi_app.include_router(tasks_router, prefix="/tasks")
    fastapi_app.include_router(workers_router, prefix="/workers")
    return fastapi_app