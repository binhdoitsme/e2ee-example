from pathlib import Path
from fastapi.staticfiles import StaticFiles
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from controllers.key_controller import KeyController
from controllers.profile_controller import ProfileController
from db.inmem_keystore import InMemoryKeyStore
from db.sqlite_profile_repository import SqliteProfileRepository
from services.decrypt_service import DecryptService
from services.key_service import KeyStore
from services.profile_service import ProfileRepository, ProfileService


def health_check():
    return {"status": "OK"}


# Get project root (parent of src folder)
PROJECT_ROOT = Path(__file__).resolve().parent.parent  # /src → project root
STATIC_DIR = PROJECT_ROOT / "static"


def main() -> None:
    app = FastAPI()

    app.get("/health")(health_check)

    origins = ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    key_store: KeyStore = InMemoryKeyStore()
    key_controller = KeyController(key_store=key_store)

    profile_repository: ProfileRepository = SqliteProfileRepository(db_path="./data.db")
    profile_service = ProfileService(profile_repository, key_store=key_store)
    decrypt_service = DecryptService(keystore=key_store)
    profile_controller = ProfileController(profile_service, decrypt_service)

    app.include_router(key_controller.router, prefix="/api/keys")
    app.include_router(profile_controller.router, prefix="/api/profiles")
    app.get("/api/health")(health_check)

    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

    uvicorn.run(app=app, port=8000, host="0.0.0.0")


if __name__ == "__main__":
    main()
