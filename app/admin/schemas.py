from pydantic import BaseModel
from typing import Optional
from uuid import UUID
from uuid import uuid4


class UserBase(BaseModel):
    email: Optional[str] = None
    isadmin: bool = False
    ip_counter: int = 0


class UserIn(UserBase):
    username: str


class UserOut(UserBase):
    id: UUID
    username: str


class UserPrivate(UserBase):
    id: UUID = uuid4()
    username: str = None
    hashed_token: Optional[str] = None


class Token(BaseModel):
    token: str