import uuid

from sqlmodel import SQLModel, Field, Relationship
from typing import Optional, List, TYPE_CHECKING

from sqlmodel import SQLModel, Relationship, Field, Column, ForeignKey, String, UUID


class ProjectUserLink(SQLModel, table=True):
    project_id: UUID = Field(
        default=None, 
        sa_column=Column(UUID, ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    )
    user_id: UUID = Field(
        default=None, 
        sa_column=Column(UUID, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    )

    class Config:
        arbitrary_types_allowed = True


class UserDB(SQLModel, table=True):
    __tablename__ = "users"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    username: str = Field(index=True)
    hashed_token: Optional[str]
    email: Optional[str]
    isadmin: bool = False
    #ip_counter: int = 0
    # disabled: bool = False

    projects: List["ProjectDB"] = Relationship(back_populates="users", link_model=ProjectUserLink)


class ProjectDB(SQLModel, table=True):
    __tablename__ = "projects"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, unique=True)
    project_name: str = Field(default=None, index=True)
    #start_date: Optional[date]
    #end_date: Optional[date]
    #scope: Optional[str] = Field(sa_column=Column(JSON))
    # archived: Optional[bool] = False

    users: List["UserDB"] = Relationship(back_populates="projects", link_model=ProjectUserLink)
    #ips: List["IPDB"] = Relationship(back_populates="project", sa_relationship_kwargs={"cascade": "all, delete"})
    #creds: List["CredentialDB"] = Relationship(back_populates="project", sa_relationship_kwargs={"cascade": "all, delete"})
    #hosts: List["HostDB"] = Relationship(back_populates="project", sa_relationship_kwargs={"cascade": "all, delete"})
