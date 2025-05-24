import os
from enum import Enum

from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    development = "development"
    production = "production"


class Config(BaseSettings):
    scanledger_base_url: str
    tasker_auth_token: str

    # Redis
    redis_host: str
    redis_port: int
    redis_password: str
    redis_db: int

    # RabbitMQ
    rabbitmq_host: str
    rabbitmq_port: int = 5672
    rabbitmq_user: str
    rabbitmq_password: str
    rabbitmq_vhost: str

    # Celery
    celery_app_name: str = "tasker"
    nmap_exchange_name: str = "nmap_exchange"
    exchange_type: str = "topic"
    nmap_scan_queue_name: str = "nmap_scan_queue"
    nmap_cancel_queue_name: str = "nmap_cancel_queue"
    nmap_scan_routing_key: str = "nmap.scan"
    nmap_cancel_routing_key: str = "nmap.cancel"

    # File upload
    max_file_upload_size: int = 1_000_000  # 1 MB
    default_chunk_size: int = 1024

    # Logger
    logger_level: str = "INFO"
    logger_name: str = "tasker_logger"

    # Database
    postgres_user: str
    postgres_password: str
    postgres_host: str
    postgres_port: int = 5432
    postgres_db: str
    tasker_default_username: str = "tasker"

    environment: str = Environment.development
    
    docs_url: str | None = None
    redoc_url: str | None = None

    # Concurrency
    concurrency_factor: int = 5
    max_semaphore_limit: int = 50

    model_config = SettingsConfigDict(env_file=".env")

    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"
    
    @property
    def rabbitmq_url(self) -> str:
        return f"pyamqp://{self.rabbitmq_user}:{self.rabbitmq_password}@{self.rabbitmq_host}:{self.rabbitmq_port}/{self.rabbitmq_vhost}"

    @property
    def optimal_semaphore(self) -> int:
        cpu_count = os.cpu_count() or 1
        return min(cpu_count * self.concurrency_factor, self.max_semaphore_limit)

    @property
    def cpu_count(self) -> int:
        return os.cpu_count() or 1

    def configure(self):
        if self.environment == Environment.development:
            self.logger_level = "DEBUG"
        elif self.environment == Environment.production:
            self.logger_level = "INFO"
            self.docs_url = None
            self.redoc_url = None


config = Config()
config.configure()