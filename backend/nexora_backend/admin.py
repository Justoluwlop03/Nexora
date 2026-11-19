from __future__ import annotations

import getpass
from pathlib import Path

from .config import Config
from .database import Database
from .service import BackendService, DomainError


def main() -> None:
    config = Config.from_environment()
    database = Database(config.database_path, config.database_url)
    database.initialize()
    email = input("Administrator email: ").strip()
    password = getpass.getpass("Administrator password (at least 16 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    try:
        user = BackendService(database).create_admin(email, password)
    except DomainError as exc:
        raise SystemExit(f"{exc.code}: {exc.message}") from exc
    print(f"Administrator created: {user['email']} ({user['id']})")
    database_label = (
        "PostgreSQL"
        if config.database_url
        else str(Path(config.database_path).resolve())
    )
    print(f"Database: {database_label}")


if __name__ == "__main__":
    main()
