import sqlite3
from uuid import UUID, uuid4
from services.profile_service import Profile, ProfileRepository


class SqliteProfileRepository(ProfileRepository):
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        # TODO: Initialize SQLite connection here

        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                encrypted_national_id BLOB,
                encryption_index BLOB
            )
        """
        )
        # create index on encryption_index for faster lookups
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_encryption_index
            ON profiles (encryption_index)
        """
        )
        self.conn.commit()

    async def save(self, profile: Profile) -> str:
        # ensure profile has an id (UUID)
        if profile.id is None:
            profile.id = uuid4()
        id_str = str(profile.id)

        self.conn.execute(
            """
            INSERT OR REPLACE INTO profiles (
                id,
                encrypted_national_id,
                encryption_index
            ) VALUES (?, ?, ?)
        """,
            (
                id_str,
                profile.encrypted_national_id,
                profile.encryption_index,
            ),
        )
        self.conn.commit()
        return id_str

    async def find_by_encryption_index(self, index: bytes) -> list[Profile]:
        """Find profile by encryption_index. Index can be non-unique, so fetch and return all matches."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT id, encrypted_national_id, encryption_index
            FROM profiles
            WHERE encryption_index = ?
        """,
            (index,),
        )
        rows = cursor.fetchall()
        if not rows:
            return []
        return [
            Profile(
                national_id="",
                id=UUID(row[0]),
                encrypted_national_id=row[1],
                encryption_index=row[2],
            )
            for row in rows
        ]
