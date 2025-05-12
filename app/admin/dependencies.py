import uuid
from typing import Annotated, Optional, Tuple

from fastapi import HTTPException, status, Depends, Path
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import select
from sqlalchemy.orm import joinedload

from .utils import hash_password_without_salt
from .schemas import UserPrivate
from .service import userdb_by_token
from .models import UserDB

from app.database import get_session, select_one
from app.admin.models import ProjectDB
from app.logger import logger
from app.constants.messages import Message


bearer_scheme = HTTPBearer(auto_error=False)


async def get_user_by_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)]
) -> Optional[UserPrivate]:
    """Retrieves the current user based on the provided token."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=Message.INVALID_AUTHENTICATION,
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    hashed_token = hash_password_without_salt(token)
    current_user = await userdb_by_token(hashed_token)
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=Message.INVALID_AUTHENTICATION,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


async def validate_user_access(
    current_user: Annotated[Optional[UserDB], Depends(get_user_by_token)]
) -> UserDB:
    """ Ensures the current user is authenticated and active. """
    if current_user is None: #or not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=Message.INVALID_AUTHENTICATION,
            headers={"WWW-Authenticate": "Bearer"},
        )
    logger.debug(f"User {current_user.username} is active and authenticated")
    return current_user


async def validate_admin_access(
    current_user: Annotated[Optional[UserPrivate], Depends(get_user_by_token)]
) -> bool:
    """ Checks if the current user has administrative access. """
    if current_user is None or not current_user.isadmin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=Message.INVALID_AUTHENTICATION,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


async def validate_user_project_access(
    project_id: uuid.UUID,
    current_user: UserPrivate
) -> Tuple[ProjectDB, UserPrivate]:
    statement = select(ProjectDB).where(
        ProjectDB.id == project_id,
        ProjectDB.users.any(id=current_user.id)
    )
    projectdb = await select_one(statement)
    if projectdb is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=Message.INVALID_AUTHENTICATION,
            headers={"WWW-Authenticate": "Bearer"},
        )

    logger.debug(f"User {current_user.username} has access to project {project_id}")
    return projectdb, current_user


async def validate_admin_project_access(
    project_id: uuid.UUID,
    current_user: UserPrivate
) -> Tuple[ProjectDB, UserPrivate]:
    statement = select(ProjectDB).where(ProjectDB.id == project_id)
    projectdb = await select_one(statement)
    if projectdb is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=Message.PROJECT_NOT_FOUND,
        )
    return projectdb, current_user


async def validate_project_access(
    project_id: Annotated[uuid.UUID, Path()] ,
    current_user: Annotated[UserPrivate, Depends(get_user_by_token)]
) -> Tuple[ProjectDB, UserPrivate]:
    if current_user.isadmin:
        return await validate_admin_project_access(project_id, current_user)
    return await validate_user_project_access(project_id, current_user)