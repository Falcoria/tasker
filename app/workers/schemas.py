from enum import Enum

from pydantic import BaseModel


class TaskNames(str, Enum):
    UPDATE_WORKER_IP = "worker.update_ip"


class WorkerIPData(BaseModel):
    ip: str
    last_updated: int