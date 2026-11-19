from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent.parent


def _load_backend_dotenv() -> None:
    """Load backend/.env without overriding variables supplied by the shell."""
    env_file = BACKEND_DIR / ".env"
    try:
        lines = env_file.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '\"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


@dataclass(frozen=True)
class Config:
    database_path: Path
    host: str = "127.0.0.1"
    port: int = 8000
    secure_cookies: bool = False
    session_days: int = 7
    database_url: str | None = None
    frontend_origin: str | None = "http://localhost:5173"
    cookie_samesite: str = "Strict"

    @classmethod
    def from_environment(cls) -> Config:
        _load_backend_dotenv()
        # Render provides PORT automatically. Keep NEXORA_PORT as an explicit
        # override for local/dev deployments and other hosting platforms.
        raw_port = os.environ.get("NEXORA_PORT") or os.environ.get("PORT", "8000")
        try:
            port = int(raw_port)
        except ValueError as exc:
            raise ValueError("NEXORA_PORT must be an integer.") from exc
        if not 1 <= port <= 65535:
            raise ValueError("NEXORA_PORT must be between 1 and 65535.")

        raw_days = os.environ.get("NEXORA_SESSION_DAYS", "7")
        try:
            session_days = int(raw_days)
        except ValueError as exc:
            raise ValueError("NEXORA_SESSION_DAYS must be an integer.") from exc
        if not 1 <= session_days <= 90:
            raise ValueError("NEXORA_SESSION_DAYS must be between 1 and 90.")

        raw_database = os.environ.get("NEXORA_DATABASE_URL") or os.environ.get(
            "NEXORA_DATABASE",
            str(BACKEND_DIR / "data" / "nexora.sqlite3"),
        )
        database_url = (
            raw_database
            if raw_database.startswith(("postgresql://", "postgres://"))
            else None
        )
        database_path = (
            BACKEND_DIR / "data" / "nexora.sqlite3"
            if database_url
            else Path(raw_database).expanduser()
        )

        secure_cookies = os.environ.get("NEXORA_SECURE_COOKIES", "false").lower() in {
            "1",
            "true",
            "yes",
        }
        cookie_samesite = os.environ.get("NEXORA_COOKIE_SAMESITE", "Strict").capitalize()
        if cookie_samesite not in {"Strict", "Lax", "None"}:
            raise ValueError("NEXORA_COOKIE_SAMESITE must be Strict, Lax, or None.")
        if cookie_samesite == "None" and not secure_cookies:
            raise ValueError("NEXORA_COOKIE_SAMESITE=None requires NEXORA_SECURE_COOKIES=true.")

        frontend_origin = os.environ.get(
            "NEXORA_FRONTEND_ORIGIN",
            "http://localhost:5173",
        ).rstrip("/")
        if frontend_origin and not frontend_origin.startswith(("http://", "https://")):
            raise ValueError("NEXORA_FRONTEND_ORIGIN must be an http(s) origin.")

        return cls(
            database_path=database_path,
            # Bind publicly when a platform supplies PORT; retain loopback for
            # local development unless NEXORA_HOST is explicitly configured.
            host=os.environ.get(
                "NEXORA_HOST",
                "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1",
            ),
            port=port,
            secure_cookies=secure_cookies,
            session_days=session_days,
            database_url=database_url,
            frontend_origin=frontend_origin or None,
            cookie_samesite=cookie_samesite,
        )
