from typing import Protocol


class KeyStore(Protocol):
    """
    KeyStore protocol for retrieving server keys.
    """

    async def get_server_pk(self, version: str = "latest") -> str: ...
    def get_private_key(self, version: str = "latest") -> bytes: ...
