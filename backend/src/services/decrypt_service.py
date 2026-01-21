import json
import base64
from typing import Any, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import AliasChoices, BaseModel, Field

from services.key_service import KeyStore


class EncryptedPayload(BaseModel):
    # incoming fields may be raw bytes or base64-encoded strings (from JSON)
    encrypted_key: Union[bytes, str] = Field(
        ..., validation_alias=AliasChoices("encryptedKey", "encrypted_key")
    )
    encrypted_payload: Union[bytes, str] = Field(
        ..., validation_alias=AliasChoices("encryptedPayload", "encrypted_payload")
    )


class DecryptService:
    """
    DecryptService handles decryption of payloads using the server's private key.
    If the system will have a lot of E2EE endpoints, consider moving this to a middleware.
    """

    def __init__(self, keystore: KeyStore) -> None:
        self.keystore = keystore

    async def decrypt(self, payload: EncryptedPayload) -> dict[str, Any]:
        # Load private key
        priv_pem = self.keystore.get_private_key()
        priv = serialization.load_pem_private_key(priv_pem, password=None)

        # Ensure we have an RSA private key so .decrypt is available
        if not isinstance(priv, RSAPrivateKey):
            raise TypeError(
                "Loaded private key is not an RSA private key and cannot decrypt the symmetric key"
            )

        # Normalize fields: accept bytes or base64-encoded strings
        def _as_bytes(v: Union[bytes, str]) -> bytes:
            if isinstance(v, bytes):
                return v
            if isinstance(v, str):
                try:
                    return base64.b64decode(v)
                except Exception:
                    # treat as raw UTF-8 if not base64
                    return v.encode("utf-8")
            raise TypeError("encrypted fields must be bytes or base64 strings")

        enc_key = _as_bytes(payload.encrypted_key)
        enc_payload = _as_bytes(payload.encrypted_payload)

        # IV is the first 12 bytes of the encrypted_payload (AES-GCM nonce)
        if len(enc_payload) < 12:
            raise ValueError("encrypted_payload is too short to contain the 12-byte IV and ciphertext")

        iv = enc_payload[:12]
        enc_payload = enc_payload[12:]

        # Validate RSA ciphertext length to avoid confusing low-level error
        rsa_modulus_bytes = priv.key_size // 8
        if len(enc_key) != rsa_modulus_bytes:
            raise ValueError(
                f"RSA ciphertext length mismatch: expected {rsa_modulus_bytes} bytes "
                f"(key size) but got {len(enc_key)} bytes. Ensure the client encrypted "
                "the exported symmetric key with the server's RSA public key using RSA-OAEP."
            )

        # Decrypt the symmetric key (RSA-OAEP)
        symmetric_key = priv.decrypt(
            enc_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt the payload using AES-GCM
        aesgcm = AESGCM(symmetric_key)
        decrypted_data = aesgcm.decrypt(iv, enc_payload, None)

        return json.loads(decrypted_data.decode("utf-8"))
