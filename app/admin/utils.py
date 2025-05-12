import hashlib
import string
import secrets


def hash_password_without_salt(password):
    return hashlib.sha256(password.encode()).hexdigest()


def generate_secure_random_string(length=128):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for i in range(length))