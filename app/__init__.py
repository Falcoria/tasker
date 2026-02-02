import contextlib

from fastapi import Depends, FastAPI

from app.config import config
from app.tasks.router import tasks_router
from app.workers.router import workers_router
from app.error_handlers import register_error_handlers
from app.workers.service import register_periodic_update_worker_ip_task

from app.admin.dependencies import validate_user_access


@contextlib.asynccontextmanager
async def app_lifespan(app: FastAPI):
    # List of background tasks and stop events
    lifespan_scope_tasks = []

    # Register background tasks
    register_periodic_update_worker_ip_task(lifespan_scope_tasks)

    try:
        yield  # app runs here
    finally:
        # On shutdown → stop all background tasks cleanly
        for task, stop_event in lifespan_scope_tasks:
            stop_event.set()
            await task


def create_app():
    fastapi_app = FastAPI(
        docs_url=config.docs_url, 
        redoc_url=config.redoc_url,
        lifespan=app_lifespan
    )

    # Register error handlers
    register_error_handlers(fastapi_app)

    fastapi_app.include_router(tasks_router, prefix="/tasks")
    fastapi_app.include_router(workers_router, prefix="/workers", dependencies=[Depends(validate_user_access)])
    return fastapi_app