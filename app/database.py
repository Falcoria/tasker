import asyncpg

from typing import AsyncGenerator

from sqlmodel import SQLModel, create_engine, delete
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio.engine import AsyncEngine
from sqlalchemy.orm import sessionmaker
from contextlib import asynccontextmanager

from app.config import config
from app.logger import logger


database_url = (
    f"postgresql+asyncpg://{config.postgres_user}:"
    f"{config.postgres_password}@{config.postgres_host}:"
    f"{config.postgres_port}/{config.postgres_db}"
)

engine = AsyncEngine(create_engine(database_url, echo=True, future=True))


async def connect_create_if_not_exists():
    try:
        # Try connecting to the target database
        conn = await asyncpg.connect(
            user=config.postgres_user,
            password=config.postgres_password,
            host=config.postgres_host,
            port=config.postgres_port,
            database=config.postgres_db
        )
        await conn.close()
    except asyncpg.InvalidCatalogNameError:
        # If database does not exist, connect to template1 and create it
        sys_conn = await asyncpg.connect(
            user=config.postgres_user,
            password=config.postgres_password,
            host=config.postgres_host,
            port=config.postgres_port,
            database="template1"
        )
        await sys_conn.execute(
            f'CREATE DATABASE "{config.postgres_db}" OWNER "{config.postgres_user}"'
        )
        await sys_conn.close()


async def init_db():
    """Initialize the database"""
    await connect_create_if_not_exists()

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


async def delete_all_tables():
    """Delete all tables from the database"""
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get an async session"""
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session


async def select_one(statement):
    """Select one row from the database"""
    async with get_session() as session:
        try:
            result = await session.exec(statement)
            return result.first()
        except Exception as e:
            logger.error(f"Exception. {e}")
            return None


async def select_many(statement):
    """Select many rows from the database"""
    async with get_session() as session:
        try:
            result = await session.exec(statement)
            return result.unique().all()
        except Exception as e:
            logger.error(f"Exception. {e}")
            return None


async def delete_and_commit(statement):
    """Delete a row from the database"""
    async with get_session() as session:
        try:
            result = await session.exec(statement)
            await session.commit()
            if result.rowcount < 1:
                return None
            return True
        except Exception as e:
            
            return None


async def insert_one(obj: object):
    """Insert a row into the database"""
    async with get_session() as session:
        session.add(obj)
        try:
            await session.commit()
            return True
        except Exception as e:
            logger.error(f"Exception. {e}")
            await session.rollback()
            return None


async def insert_and_refresh(obj: object):
    """Insert a row into the database and refresh"""
    async with get_session() as session:
        session.add(obj)
        try:
            await session.commit()
            await session.refresh(obj)
            return obj
        except Exception as e:
            logger.error(f"Exception. {e}")
            await session.rollback()
            return None