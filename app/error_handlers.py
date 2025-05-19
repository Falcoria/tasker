from fastapi import Request, FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import JSONResponse
from app.config import config, Environment


def register_error_handlers(app: FastAPI):
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        detail = exc.detail if config.environment == Environment.development else "An error occurred"
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": detail},
        )


    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        if config.environment == Environment.development:
            return JSONResponse(
                status_code=422,
                content={"detail": exc.errors()},
            )
        else:
            return JSONResponse(
                status_code=422,
                content={"detail": "Invalid request"},
            )
