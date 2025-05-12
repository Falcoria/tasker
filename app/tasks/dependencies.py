import os

from typing import Annotated, Union

import aiofiles
from fastapi import HTTPException, status, UploadFile, File, Body

from pydantic import Field

from app.config import config
from app.constants.messages import Message
from app.config import config

from .schemas import OpenPortsOpts, ServiceOpts


async def file_upload(
    file: UploadFile = File(..., description="File to upload"),
) -> str:
    """ Dependancy for file upload. Saves uploaded file to tmp, checks size of uploaded file, returns path"""
    if file.size == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=Message.EMPTY_FILE
        )

    max_size = config.max_file_upload_size
    real_file_size = 0
    temp_name = None
    async with aiofiles.tempfile.NamedTemporaryFile(delete=False) as temp:
        temp_name = temp.name
        while chunk := await file.read(config.default_chunk_size):
            real_file_size += len(chunk)
            if real_file_size > max_size:
                os.remove(temp_name)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, 
                    detail=Message.FILE_TOO_LARGE
                )
            await temp.write(chunk)    
    return temp_name


def check_open_ports_opts(
    open_ports_opts: OpenPortsOpts = OpenPortsOpts()
) -> OpenPortsOpts:
    if not open_ports_opts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=Message.INVALID_OPEN_PORTS_OPTS
        )
    return open_ports_opts


def check_service_opts(
    service_ports_opts: Annotated[ServiceOpts, Body()]
) -> str:
    if not service_ports_opts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=Message.INVALID_SERVICE_OPTS
        )
    return service_ports_opts