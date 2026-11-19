from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Protocol, Sequence


ASSETS = (
    ("BTC", 8, ("Bitcoin",)),
    ("ETH", 18, ("Ethereum-ERC20",)),
    ("USDT", 6, ("Ethereum-ERC20", "Tron-TRC20")),
    ("USDC", 6, ("Ethereum-ERC20",)),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
    created_at TEXT NOT NULL,
    deleted_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    csrf_token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);

CREATE TABLE IF NOT EXISTS assets (
    symbol TEXT PRIMARY KEY,
    decimals INTEGER NOT NULL CHECK (decimals BETWEEN 0 AND 30),
    networks_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    owner_id TEXT REFERENCES users(id),
    asset TEXT NOT NULL REFERENCES assets(symbol),
    bucket TEXT NOT NULL CHECK (bucket IN ('available', 'investment', 'system')),
    reference TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS accounts_owner_bucket_reference_idx
    ON accounts(owner_id, asset, bucket, reference);
CREATE TABLE IF NOT EXISTS balance_projection (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id),
    amount_atomic TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS journal_transactions (
    id TEXT PRIMARY KEY,
    reference TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    actor_id TEXT REFERENCES users(id),
    idempotency_key TEXT,
    payload_hash TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS journal_idempotency_idx
    ON journal_transactions(actor_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS journal_entries (
    id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL REFERENCES journal_transactions(id),
    account_id TEXT NOT NULL REFERENCES accounts(id),
    amount_atomic TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS journal_entries_account_idx
    ON journal_entries(account_id, transaction_id);

CREATE TABLE IF NOT EXISTS investments (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    asset TEXT NOT NULL REFERENCES assets(symbol),
    principal_atomic TEXT NOT NULL,
    terms_json TEXT NOT NULL,
    cycles_completed INTEGER NOT NULL DEFAULT 0 CHECK (cycles_completed >= 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'completed', 'cancelled')),
    transaction_id TEXT NOT NULL REFERENCES journal_transactions(id),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS investments_user_idx ON investments(user_id, created_at);

CREATE TABLE IF NOT EXISTS deposit_addresses (
    asset TEXT NOT NULL REFERENCES assets(symbol),
    network TEXT NOT NULL,
    address TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    updated_by TEXT NOT NULL REFERENCES users(id),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (asset, network)
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS withdrawal_eligibility (
    user_id TEXT NOT NULL REFERENCES users(id),
    asset TEXT NOT NULL REFERENCES assets(symbol),
    fee_atomic TEXT NOT NULL,
    paid_at TEXT NOT NULL,
    consumed_at TEXT,
    payment_transaction_id TEXT NOT NULL REFERENCES journal_transactions(id),
    PRIMARY KEY (user_id, asset)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    reason TEXT NOT NULL,
    request_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events(created_at);

"""

SQLITE_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS journal_entries_no_update
BEFORE UPDATE ON journal_entries BEGIN
    SELECT RAISE(ABORT, 'journal entries are immutable');
END;
CREATE TRIGGER IF NOT EXISTS journal_entries_no_delete
BEFORE DELETE ON journal_entries BEGIN
    SELECT RAISE(ABORT, 'journal entries are immutable');
END;
CREATE TRIGGER IF NOT EXISTS journal_transactions_no_update
BEFORE UPDATE ON journal_transactions BEGIN
    SELECT RAISE(ABORT, 'journal transactions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS journal_transactions_no_delete
BEFORE DELETE ON journal_transactions BEGIN
    SELECT RAISE(ABORT, 'journal transactions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events BEGIN
    SELECT RAISE(ABORT, 'audit events are immutable');
END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events BEGIN
    SELECT RAISE(ABORT, 'audit events are immutable');
END;
"""

POSTGRES_IMMUTABILITY = """
CREATE OR REPLACE FUNCTION nexora_prevent_immutable_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END;
$$
"""

POSTGRES_TRIGGERS = (
    ("journal_entries", "journal_entries_no_update", "UPDATE"),
    ("journal_entries", "journal_entries_no_delete", "DELETE"),
    ("journal_transactions", "journal_transactions_no_update", "UPDATE"),
    ("journal_transactions", "journal_transactions_no_delete", "DELETE"),
    ("audit_events", "audit_events_no_update", "UPDATE"),
    ("audit_events", "audit_events_no_delete", "DELETE"),
)


class DatabaseConnection(Protocol):
    def execute(
        self,
        query: str,
        parameters: Sequence[Any] = (),
    ) -> Any: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


class Database:
    def __init__(self, path: Path, database_url: str | None = None) -> None:
        self.path = path
        self.database_url = database_url

    def connect(self) -> DatabaseConnection:
        if self.database_url:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as exc:
                raise RuntimeError(
                    "PostgreSQL support requires psycopg. Install the backend dependencies."
                ) from exc
            return _PostgresConnection(
                psycopg.connect(self.database_url, row_factory=dict_row)
            )

        connection = sqlite3.connect(
            self.path,
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def initialize(self) -> None:
        if self.database_url:
            self._initialize_postgres()
            return

        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self.connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(SCHEMA + SQLITE_TRIGGERS)
            user_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(users)").fetchall()
            }
            if "deleted_at" not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN deleted_at TEXT")
            for symbol, decimals, networks in ASSETS:
                connection.execute(
                    """
                    INSERT INTO assets (symbol, decimals, networks_json)
                    VALUES (?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """,
                    (symbol, decimals, json.dumps(networks)),
                )
                connection.execute(
                    """
                    INSERT INTO accounts
                        (id, owner_id, asset, bucket, reference, created_at)
                    VALUES (?, NULL, ?, 'system', 'issuance', '1970-01-01T00:00:00+00:00')
                    ON CONFLICT DO NOTHING
                    """,
                    (f"system-{symbol}", symbol),
                )
                connection.execute(
                    """
                    INSERT INTO balance_projection (account_id, amount_atomic)
                    VALUES (?, '0')
                    ON CONFLICT DO NOTHING
                    """,
                    (f"system-{symbol}",),
                )
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[DatabaseConnection]:
        connection = self.connect()
        try:
            if self.database_url:
                connection.execute("SELECT pg_advisory_xact_lock(741852963)")
            else:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def check(self) -> None:
        connection = self.connect()
        try:
            connection.execute("SELECT 1").fetchone()
        finally:
            connection.close()

    @staticmethod
    def is_integrity_error(exc: Exception) -> bool:
        if isinstance(exc, sqlite3.IntegrityError):
            return True
        try:
            import psycopg
        except ImportError:
            return False
        return isinstance(exc, psycopg.IntegrityError)

    def _initialize_postgres(self) -> None:
        connection = self.connect()
        try:
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    connection.execute(statement)
            connection.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TEXT")
            connection.execute(POSTGRES_IMMUTABILITY)
            for table, trigger, operation in POSTGRES_TRIGGERS:
                connection.execute(f"DROP TRIGGER IF EXISTS {trigger} ON {table}")
                connection.execute(
                    f"CREATE TRIGGER {trigger} BEFORE {operation} ON {table} "
                    "FOR EACH ROW EXECUTE FUNCTION nexora_prevent_immutable_mutation()"
                )
            for symbol, decimals, networks in ASSETS:
                connection.execute(
                    """
                    INSERT INTO assets (symbol, decimals, networks_json)
                    VALUES (?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """,
                    (symbol, decimals, json.dumps(networks)),
                )
                connection.execute(
                    """
                    INSERT INTO accounts
                        (id, owner_id, asset, bucket, reference, created_at)
                    VALUES (?, NULL, ?, 'system', 'issuance', '1970-01-01T00:00:00+00:00')
                    ON CONFLICT DO NOTHING
                    """,
                    (f"system-{symbol}", symbol),
                )
                connection.execute(
                    """
                    INSERT INTO balance_projection (account_id, amount_atomic)
                    VALUES (?, '0')
                    ON CONFLICT DO NOTHING
                    """,
                    (f"system-{symbol}",),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class _PostgresConnection:
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def execute(self, query: str, parameters: Sequence[Any] = ()) -> Any:
        query = query.replace("owner_id IS ?", "owner_id IS NOT DISTINCT FROM ?")
        query = query.replace("?", "%s")
        return self._connection.execute(query, parameters)

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()
