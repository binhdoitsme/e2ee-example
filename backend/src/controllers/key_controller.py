from typing import Any

from fastapi.routing import APIRouter

from services.key_service import KeyStore


class KeyController:
    def __init__(
        self, key_store: KeyStore, router: APIRouter = APIRouter()
    ) -> None:
        self.key_store = key_store
        self.router = router
        # define routes here
        self.router.get("")(self.get_server_key)

    async def get_server_key(self) -> dict[str, Any]:
        return {"publicKey": await self.key_store.get_server_pk()}
