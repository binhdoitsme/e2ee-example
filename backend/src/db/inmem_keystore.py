from services.key_service import KeyStore
from pathlib import Path
import base64
import asyncio
import re


class InMemoryKeyStore(KeyStore):
    async def get_server_pk(self, version: str = "latest") -> str:
        """Return the server public key encoded as base64.

        If `version` is a concrete version string, the function looks for
        files named `rsa_public_{version}.pem` in the project root and
        `keys/` subdirectory. If `version == "latest"`, the function
        selects the most-recently modified file among files matching
        `rsa_public_*.pem` (and also considers `rsa_public.pem` as a
        fallback), then returns its base64-encoded contents.

        File I/O is performed via `asyncio.to_thread` to avoid blocking.
        """
        # project layout: src/ is inside project root; keys live at project root
        # `parents[2]` moves from src/db -> src -> project root
        base_dir = Path(__file__).resolve().parents[2]
        # search project root and keys/, but keep src/ and src/keys/ as fallbacks
        search_dirs = [base_dir, base_dir / "keys", base_dir / "src", base_dir / "src" / "keys"]

        # If a specific version was requested, try to find that exact file.
        if version != "latest":
            target_name = f"rsa_public_{version}.pem"
            for d in search_dirs:
                p = d / target_name
                if p.exists():
                    data = await asyncio.to_thread(p.read_bytes)
                    return base64.b64encode(data).decode("utf-8")

            raise FileNotFoundError(
                f"Requested key '{target_name}' not found. Searched: "
                + ", ".join(str(d / target_name) for d in search_dirs)
            )

        # version == "latest": gather candidate files and pick newest by mtime
        candidates = list[Path]()
        for d in search_dirs:
            if not d.exists():
                continue
            candidates.extend(d.glob("rsa_public_*.pem"))
            plain = d / "rsa_public.pem"
            if plain.exists():
                candidates.append(plain)

        candidates = [p for p in candidates if p.exists()]
        if not candidates:
            searched = ", ".join(str(d / "rsa_public_*.pem") for d in search_dirs)
            raise FileNotFoundError("No rsa_public files found. Searched: " + searched)

        newest = max(candidates, key=lambda p: p.stat().st_mtime)
        data = await asyncio.to_thread(newest.read_bytes)

        # derive a version label from the filename when possible
        m = re.match(r"rsa_public_(.+)\.pem$", newest.name)
        if m:
            selected_version = m.group(1)
        elif newest.name == "rsa_public.pem":
            selected_version = "latest"
        else:
            selected_version = "latest"

        encoded = base64.b64encode(data).decode("utf-8")
        return f"{selected_version}:{encoded}"

    def get_private_key(self, version: str = "latest") -> bytes:
        """Return server private key, in key format, not base64-encoded."""
        # see comment in get_server_pk: prefer project root (one level above src)
        base_dir = Path(__file__).resolve().parents[2]
        search_dirs = [base_dir, base_dir / "keys", base_dir / "src", base_dir / "src" / "keys"]

        # If a specific version was requested, try to find that exact file.
        if version != "latest":
            target_name = f"rsa_private_{version}.pem"
            for d in search_dirs:
                p = d / target_name
                if p.exists():
                    return p.read_bytes()

            raise FileNotFoundError(
                f"Requested key '{target_name}' not found. Searched: "
                + ", ".join(str(d / target_name) for d in search_dirs)
            )

        # version == "latest": gather candidate files and pick newest by mtime
        candidates = list[Path]()
        for d in search_dirs:
            if not d.exists():
                continue
            candidates.extend(d.glob("rsa_private_*.pem"))
            plain = d / "rsa_private.pem"
            if plain.exists():
                candidates.append(plain)

        candidates = [p for p in candidates if p.exists()]
        if not candidates:
            searched = ", ".join(str(d / "rsa_private_*.pem") for d in search_dirs)
            raise FileNotFoundError("No rsa_private files found. Searched: " + searched)

        newest = max(candidates, key=lambda p: p.stat().st_mtime)
        return newest.read_bytes()
