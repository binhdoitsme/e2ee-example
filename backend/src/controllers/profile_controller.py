from typing import Any

from fastapi import APIRouter, Body, Depends

from services.decrypt_service import DecryptService, EncryptedPayload
from services.profile_service import Profile, ProfileService


class ProfileController:
    def __init__(
        self,
        profile_service: ProfileService,
        decrypt_service: DecryptService,
        router: APIRouter = APIRouter(),
    ) -> None:
        self.profile_service = profile_service
        self.decrypt_service = decrypt_service
        self.router = router
        router.post("")(self.save_profile)
        router.post("/existence")(self.exists_by_national_id)

    async def save_profile(self, payload: EncryptedPayload):
        decrypted_data = await self.decrypt_service.decrypt(payload)
        profile = Profile(**decrypted_data)
        await self.profile_service.save_profile(profile)
        return {"status": "success"}

    async def exists_by_national_id(
        self, national_id: str = Body(..., embed=True)
    ) -> dict[str, bool]:
        existing = await self.profile_service.find_by_national_id(national_id)
        return {"exists": existing is not None}
