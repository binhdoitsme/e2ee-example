import hashlib
import hmac
import secrets
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import AliasChoices, BaseModel, Field

from services.key_service import KeyStore


class Profile(BaseModel):
    national_id: str = Field(
        ..., validation_alias=AliasChoices("nationalId", "national_id")
    )
    id: UUID | None = None
    encrypted_national_id: bytes | None = None
    encryption_index: bytes | None = None


class ProfileRepository(Protocol):
    """
    ProfileRepository protocol for storing and retrieving profiles.
    """

    async def save(self, profile: Profile) -> str: ...

    # this method looks up by encryption_index which can duplicate
    async def find_by_encryption_index(self, index: bytes) -> list[Profile]: ...


class ProfileService:
    """
    ProfileService handles profile data storage and existence checks.
    """

    def __init__(self, repository: ProfileRepository, key_store: KeyStore) -> None:
        self.repository = repository
        self.key_store = key_store
        priv_pem = self.key_store.get_private_key()
        priv = serialization.load_pem_private_key(priv_pem, password=None)
        priv_der = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._enc_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,  # prefer an application salt if available
            info=b"profile-enc",
        ).derive(priv_der)

        self._idx_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"profile-idx",
        ).derive(priv_der)

    async def save_profile(self, profile: Profile):
        # encrypt national_id using randomized AES-GCM
        encrypted_national_id = self._encrypt(profile.national_id)
        # create index using deterministic HMAC-SHA256
        index = self._create_index(profile.national_id)
        profile.id = profile.id or uuid4()
        profile.encrypted_national_id = encrypted_national_id
        profile.encryption_index = index

        saved_id: str | None = None
        if self.repository is not None:
            saved_id = await self.repository.save(profile)
        # ensure we return the id string for callers
        return str(profile.id) if profile.id is not None else saved_id

    def _encrypt(self, national_id: str) -> bytes:
        """Encrypt `national_id` using AES-GCM with a random 96-bit nonce.
        Returns nonce || ciphertext bytes. Ensures the key length is valid for AES-GCM
        (16/24/32 bytes); if not, derive a 32-byte key via SHA-256 of the configured key.
        """
        key = self._enc_key
        if len(key) not in (16, 24, 32):
            key = hashlib.sha256(key).digest()
        aesgcm = AESGCM(key)
        iv = secrets.token_bytes(12)
        ct = aesgcm.encrypt(iv, national_id.encode("utf-8"), None)
        return iv + ct

    def _decrypt(self, encrypted_data: bytes) -> str:
        """Decrypt data encrypted by `_encrypt`, which is nonce || ciphertext."""
        key = self._enc_key
        if len(key) not in (16, 24, 32):
            key = hashlib.sha256(key).digest()
        iv = encrypted_data[:12]
        ct = encrypted_data[12:]
        aesgcm = AESGCM(key)
        pt = aesgcm.decrypt(iv, ct, None)
        return pt.decode("utf-8")

    def _create_index(self, national_id: str) -> bytes:
        # Deterministic HMAC-SHA256 over the plaintext national_id
        hm = hmac.new(self._idx_key, digestmod=hashlib.sha256)
        hm.update(national_id.encode("utf-8"))
        return hm.digest()

    async def find_by_national_id(self, exact_national_id: str) -> Profile | None:
        index = self._create_index(exact_national_id)
        if self.repository is None:
            return None
        candidates = await self.repository.find_by_encryption_index(index)
        for profile in candidates:
            decrypted_id = self._decrypt(profile.encrypted_national_id or bytes())
            if decrypted_id == exact_national_id:
                return profile

        return None
