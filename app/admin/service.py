
from sqlmodel import select, update, delete

from app.database import select_one

from .models import UserDB
from .utils import hash_password_without_salt, generate_secure_random_string


async def generate_unique_token(token_length=60):
    """
    Generates a unique token and checks if its hash already exists in the database.
    Continues to regenerate the token until a unique one is found.
    """
    while True:
        token = generate_secure_random_string(token_length)
        hashed_token = hash_password_without_salt(token)

        statement = select(UserDB).where(UserDB.hashed_token == hashed_token)
        result = await select_one(statement)
        if result is None:
            return token


async def userdb_by_token(hashed_token: str) -> UserDB:
    """ Get a user by hashed token """
    statement = select(UserDB).where(UserDB.hashed_token == hashed_token)
    user_db = await select_one(statement)
    return user_db