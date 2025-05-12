from app import create_app

fastapi_app = create_app()

@fastapi_app.get("/health")
def status():
    return {"status": "ok"}
