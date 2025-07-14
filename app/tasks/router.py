from typing import Annotated, Tuple, List

from fastapi import APIRouter, Depends, Body

from .service import send_nmap_tasks, revoke_project_tasks, get_scan_status
from .schemas import RunNmapRequest, RunNmapWithProject

from app.admin.dependencies import validate_project_access
from app.admin.models import UserDB, ProjectDB


tasks_router = APIRouter()


@tasks_router.post(
        "/{project_id}/run-nmap",
        summary="Run Nmap",
        description="Run Nmap on the provided file",
        tags=["tasks"]
    )
async def run_nmap(
    project_and_user: Annotated[Tuple[ProjectDB, UserDB], Depends(validate_project_access)],
    user_data: Annotated[RunNmapRequest, Body()],
):
    project, user = project_and_user
    result = await send_nmap_tasks(user_data, project, user)
    return result


@tasks_router.get("/{project_id}/status")
async def status(
        project_and_user: Annotated[str, Depends(validate_project_access)]
    ):
    result = await get_scan_status(project_id=project_and_user[0].id)
    return result


@tasks_router.get("/{project_id}/stop-nmap")
async def delete(
    project_and_user: Annotated[Tuple[ProjectDB, UserDB], Depends(validate_project_access)],
    ):
    result = await revoke_project_tasks(
        project_id=project_and_user[0].id
    )
    return result


