from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .database import ASSETS, Database, DatabaseConnection

PASSWORD_ITERATIONS = 310_000
PASSWORD_MIN_LENGTH = 12
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+$")
DEMO_ADDRESS_RE = re.compile(r"^DEMO-[A-Z0-9-]{4,80}$")
DEPOSIT_ADDRESS_PATTERNS = {
    "Bitcoin": re.compile(r"^(?:(?i:bc1[a-z0-9]{11,59})|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$"),
    "Ethereum-ERC20": re.compile(r"^0x[a-fA-F0-9]{40}$"),
    "Tron-TRC20": re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$"),
}
ASSET_DECIMALS = {symbol: decimals for symbol, decimals, _ in ASSETS}
ASSET_NETWORKS = {
    symbol: set(networks)
    for symbol, _, networks in ASSETS
}
WITHDRAWAL_FEES = {"BTC": "0.00012", "ETH": "0.0015", "USDT": "2.5", "USDC": "2.5"}


class DomainError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime | None = None) -> str:
    return (value or utc_now()).isoformat(timespec="seconds")


def opaque_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def normalize_email(value: Any) -> str:
    if not isinstance(value, str):
        raise DomainError(422, "INVALID_EMAIL", "Enter a valid email address.")
    email = value.strip().lower()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise DomainError(422, "INVALID_EMAIL", "Enter a valid email address.")
    return email


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
    )
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, raw_iterations, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(raw_iterations)
        if not PASSWORD_ITERATIONS <= iterations <= PASSWORD_ITERATIONS * 4:
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            iterations,
        ).hex()
        return hmac.compare_digest(actual, digest_hex)
    except (ValueError, TypeError):
        return False


def parse_amount(value: Any, asset: str) -> int:
    if asset not in ASSET_DECIMALS:
        raise DomainError(422, "UNSUPPORTED_ASSET", "Choose a supported asset.")
    if not isinstance(value, str) or not value or len(value) > 80:
        raise DomainError(422, "INVALID_AMOUNT", "Enter a valid positive amount.")
    if not re.fullmatch(r"(?:0|[1-9]\d*)(?:\.\d+)?", value):
        raise DomainError(422, "INVALID_AMOUNT", "Enter a valid positive amount.")

    whole, _, fraction = value.partition(".")
    decimals = ASSET_DECIMALS[asset]
    if len(fraction) > decimals:
        raise DomainError(
            422,
            "INVALID_PRECISION",
            f"{asset} supports at most {decimals} decimal places.",
        )
    atomic = int(whole) * (10**decimals)
    if fraction:
        atomic += int(fraction.ljust(decimals, "0"))
    if atomic <= 0:
        raise DomainError(422, "INVALID_AMOUNT", "Enter a valid positive amount.")
    return atomic


def format_amount(atomic: int | str, asset: str) -> str:
    decimals = ASSET_DECIMALS[asset]
    value = int(atomic)
    sign = "-" if value < 0 else ""
    value = abs(value)
    scale = 10**decimals
    whole, fraction = divmod(value, scale)
    if not decimals:
        return f"{sign}{whole}"
    fraction_text = str(fraction).rjust(decimals, "0").rstrip("0")
    return f"{sign}{whole}" + (f".{fraction_text}" if fraction_text else "")


def payload_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class BackendService:
    def __init__(self, database: Database, session_days: int = 7) -> None:
        self.database = database
        self.session_days = session_days

    def create_admin(self, email: Any, password: Any) -> dict[str, str]:
        normalized_email = normalize_email(email)
        self._validate_password(password, admin=True)
        encoded = password_hash(password)
        user_id = opaque_id("usr")
        created_at = timestamp()
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO users (id, email, name, password_hash, role, status, created_at)
                    VALUES (?, ?, ?, ?, 'admin', 'active', ?)
                    """,
                    (user_id, normalized_email, "Nexora Administrator", encoded, created_at),
                )
                self._create_user_accounts(connection, user_id, created_at)
        except Exception as exc:
            if not self.database.is_integrity_error(exc):
                raise
            raise DomainError(
                409, "EMAIL_EXISTS", "An account with that email already exists."
            ) from exc
        return {"id": user_id, "email": normalized_email, "role": "admin"}

    def register(
        self,
        name: Any,
        email: Any,
        password: Any,
    ) -> tuple[dict[str, Any], str, str]:
        if not isinstance(name, str) or not 2 <= len(name.strip()) <= 80:
            raise DomainError(422, "INVALID_NAME", "Name must be between 2 and 80 characters.")
        normalized_email = normalize_email(email)
        self._validate_password(password)
        encoded = password_hash(password)
        user_id = opaque_id("usr")
        created_at = timestamp()
        session = self._new_session(user_id)
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO users (id, email, name, password_hash, role, status, created_at)
                    VALUES (?, ?, ?, ?, 'user', 'active', ?)
                    """,
                    (user_id, normalized_email, name.strip(), encoded, created_at),
                )
                self._create_user_accounts(connection, user_id, created_at)
                self._insert_session(connection, session)
        except Exception as exc:
            if not self.database.is_integrity_error(exc):
                raise
            raise DomainError(
                409, "EMAIL_EXISTS", "An account with that email already exists."
            ) from exc
        return (
            self._public_user(user_id, normalized_email, name.strip(), "user", "active", created_at),
            session["token"],
            session["csrf_token"],
        )

    def login(self, email: Any, password: Any) -> tuple[dict[str, Any], str, str]:
        normalized_email = normalize_email(email)
        if not isinstance(password, str) or len(password) > 256:
            raise DomainError(401, "INVALID_CREDENTIALS", "Email or password is incorrect.")
        connection = self.database.connect()
        try:
            row = connection.execute(
                "SELECT * FROM users WHERE email = ? AND deleted_at IS NULL",
                (normalized_email,),
            ).fetchone()
        finally:
            connection.close()
        if (
            row is None
            or row["status"] != "active"
            or not verify_password(password, row["password_hash"])
        ):
            raise DomainError(401, "INVALID_CREDENTIALS", "Email or password is incorrect.")
        session = self._new_session(row["id"])
        with self.database.transaction() as connection:
            self._insert_session(connection, session)
        return (
            self._public_user(
                row["id"],
                row["email"],
                row["name"],
                row["role"],
                row["status"],
                row["created_at"],
            ),
            session["token"],
            session["csrf_token"],
        )

    def update_admin_credentials(
        self,
        admin_id: str,
        current_password: Any,
        email: Any,
        new_password: Any,
        request_id: str,
    ) -> tuple[dict[str, str], str, str]:
        normalized_email = normalize_email(email)
        self._validate_password(new_password, admin=True)
        if not isinstance(current_password, str) or len(current_password) > 256:
            raise DomainError(401, "INVALID_CREDENTIALS", "Current password is incorrect.")

        connection = self.database.connect()
        try:
            row = connection.execute(
                "SELECT * FROM users WHERE id = ? AND role = 'admin' AND status = 'active'",
                (admin_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None or not verify_password(current_password, row["password_hash"]):
            raise DomainError(401, "INVALID_CREDENTIALS", "Current password is incorrect.")

        encoded_password = password_hash(new_password)
        session = self._new_session(admin_id)
        updated_at = timestamp()
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    "UPDATE users SET email = ?, password_hash = ? WHERE id = ?",
                    (normalized_email, encoded_password, admin_id),
                )
                connection.execute(
                    "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                    (updated_at, admin_id),
                )
                self._insert_session(connection, session)
                self._audit(
                    connection,
                    admin_id,
                    "admin_credentials_updated",
                    admin_id,
                    "Administrator updated sign-in credentials",
                    request_id,
                )
        except Exception as exc:
            if not self.database.is_integrity_error(exc):
                raise
            raise DomainError(
                409, "EMAIL_EXISTS", "An account with that email already exists."
            ) from exc

        return (
            self._public_user(
                admin_id,
                normalized_email,
                row["name"],
                "admin",
                "active",
                row["created_at"],
            ),
            session["token"],
            session["csrf_token"],
        )

    def authenticate(self, token: str | None) -> tuple[dict[str, Any], str]:
        if not token:
            raise DomainError(401, "UNAUTHENTICATED", "Sign in to continue.")
        token_hash = hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()
        connection = self.database.connect()
        try:
            row = connection.execute(
                """
                SELECT users.*, sessions.csrf_token
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ?
                  AND sessions.revoked_at IS NULL
                  AND sessions.expires_at > ?
                  AND users.deleted_at IS NULL
                """,
                (token_hash, timestamp()),
            ).fetchone()
        finally:
            connection.close()
        if row is None or row["status"] != "active":
            raise DomainError(401, "UNAUTHENTICATED", "Sign in to continue.")
        user = self._public_user(
            row["id"],
            row["email"],
            row["name"],
            row["role"],
            row["status"],
            row["created_at"],
        )
        return user, row["csrf_token"]

    def logout(self, token: str) -> None:
        token_hash = hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()
        with self.database.transaction() as connection:
            connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE token_hash = ? AND revoked_at IS NULL
                """,
                (timestamp(), token_hash),
            )

    def assets(self) -> list[dict[str, Any]]:
        return [
            {"symbol": symbol, "decimals": decimals, "networks": list(networks)}
            for symbol, decimals, networks in ASSETS
        ]

    def balances(self, user_id: str) -> list[dict[str, str]]:
        connection = self.database.connect()
        try:
            rows = connection.execute(
                """
                SELECT accounts.asset, accounts.bucket, balance_projection.amount_atomic
                FROM accounts
                JOIN balance_projection ON balance_projection.account_id = accounts.id
                WHERE accounts.owner_id = ? AND accounts.bucket IN ('available', 'investment')
                ORDER BY accounts.asset, accounts.bucket
                """,
                (user_id,),
            ).fetchall()
        finally:
            connection.close()
        result: dict[str, dict[str, str]] = {}
        for row in rows:
            result.setdefault(row["asset"], {})[row["bucket"]] = format_amount(
                row["amount_atomic"], row["asset"]
            )
        return [
            {
                "asset": symbol,
                "available": result.get(symbol, {}).get("available", "0"),
                "invested": result.get(symbol, {}).get("investment", "0"),
            }
            for symbol, _, _ in ASSETS
        ]

    def deposit_addresses(self) -> list[dict[str, str]]:
        connection = self.database.connect()
        try:
            rows = connection.execute(
                """
                SELECT asset, network, address, updated_at
                FROM deposit_addresses WHERE enabled = 1 ORDER BY asset, network
                """
            ).fetchall()
        finally:
            connection.close()
        return [dict(row) for row in rows]

    def admin_deposit_addresses(self) -> list[dict[str, Any]]:
        connection = self.database.connect()
        try:
            rows = connection.execute(
                """
                SELECT asset, network, address, enabled, updated_at
                FROM deposit_addresses ORDER BY asset, network
                """
            ).fetchall()
        finally:
            connection.close()
        return [dict(row) for row in rows]

    def withdrawal_fees(self) -> dict[str, str]:
        connection = self.database.connect()
        try:
            rows = connection.execute(
                "SELECT key, value FROM app_settings WHERE key LIKE 'withdrawal_fee_%'"
            ).fetchall()
        finally:
            connection.close()
        fees = {"USDT": WITHDRAWAL_FEES["USDT"]}
        for row in rows:
            asset = row["key"].removeprefix("withdrawal_fee_")
            if asset in fees:
                fees[asset] = row["value"]
        return fees

    @staticmethod
    def _withdrawal_fee_atomic(
        connection: DatabaseConnection,
    ) -> int:
        row = connection.execute(
            "SELECT value FROM app_settings WHERE key = 'withdrawal_fee_USDT'"
        ).fetchone()
        value = row["value"] if row is not None else WITHDRAWAL_FEES["USDT"]
        return 0 if value == "0" else parse_amount(value, "USDT")

    def withdrawal_eligibility(self, user_id: str) -> dict[str, bool]:
        connection = self.database.connect()
        try:
            result: dict[str, bool] = {}
            fee_atomic = self._withdrawal_fee_atomic(connection)
            eligibility = connection.execute(
                "SELECT fee_atomic, consumed_at FROM withdrawal_eligibility "
                "WHERE user_id = ? AND asset = 'USDT'",
                (user_id,),
            ).fetchone()
            paid = bool(
                eligibility is not None
                and eligibility["consumed_at"] is None
                and int(eligibility["fee_atomic"]) == fee_atomic
            )
            for asset, _, _ in ASSETS:
                result[asset] = fee_atomic == 0 or paid
            return result
        finally:
            connection.close()

    def pay_withdrawal_fee(
        self,
        user_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        with self.database.transaction() as connection:
            fee_asset = "USDT"
            fee_atomic = self._withdrawal_fee_atomic(connection)
            fee_destination = connection.execute(
                "SELECT network, address FROM deposit_addresses "
                "WHERE asset = 'USDT' AND enabled = 1 ORDER BY network LIMIT 1"
            ).fetchone()
            if fee_destination is None:
                raise DomainError(
                    409,
                    "WITHDRAWAL_FEE_ADDRESS_UNAVAILABLE",
                    "The administrator has not configured a USDT fee destination.",
                )
            payload = {
                "feeAsset": fee_asset,
                "feeAtomic": str(fee_atomic),
                "feeAddress": fee_destination["address"],
            }
            replay = self._idempotent(connection, user_id, idempotency_key, payload)
            if replay is not None:
                return replay
            if fee_atomic == 0:
                raise DomainError(422, "NO_FEE_REQUIRED", "No withdrawal fee is required for this asset.")
            eligibility = connection.execute(
                "SELECT fee_atomic, consumed_at FROM withdrawal_eligibility "
                "WHERE user_id = ? AND asset = ?",
                (user_id, fee_asset),
            ).fetchone()
            if (
                eligibility is not None
                and eligibility["consumed_at"] is None
                and int(eligibility["fee_atomic"]) == fee_atomic
            ):
                raise DomainError(409, "WITHDRAWAL_FEE_ALREADY_PAID", "The withdrawal fee is already paid for this asset.")
            available = self._account(connection, user_id, fee_asset, "available")
            fees = self._account(
                connection,
                None,
                fee_asset,
                "system",
                f"withdrawal_fees:{fee_destination['address']}",
            )
            self._ensure_funds(connection, available, fee_atomic)
            transaction_id = self._post(
                connection,
                kind="withdrawal_fee_payment",
                actor_id=user_id,
                entries=[(available, -fee_atomic), (fees, fee_atomic)],
                metadata={
                    "userId": user_id,
                    "asset": fee_asset,
                    "amountAtomic": str(fee_atomic),
                    "fee": format_amount(fee_atomic, fee_asset),
                    "feeAsset": fee_asset,
                    "feeAddress": fee_destination["address"],
                    "feeNetwork": fee_destination["network"],
                },
                idempotency_key=idempotency_key,
                payload=payload,
            )
            paid_at = timestamp()
            connection.execute(
                "INSERT INTO withdrawal_eligibility "
                "(user_id, asset, fee_atomic, paid_at, consumed_at, payment_transaction_id) "
                "VALUES (?, ?, ?, ?, NULL, ?) "
                "ON CONFLICT(user_id, asset) DO UPDATE SET "
                "fee_atomic = excluded.fee_atomic, paid_at = excluded.paid_at, "
                "consumed_at = NULL, payment_transaction_id = excluded.payment_transaction_id",
                (user_id, fee_asset, str(fee_atomic), paid_at, transaction_id),
            )
            return self._transaction_result(connection, transaction_id)

    def update_withdrawal_fees(
        self, actor_id: str, values: Any, reason: Any, request_id: str
    ) -> dict[str, str]:
        if not isinstance(values, dict) or set(values) != {"USDT"}:
            raise DomainError(422, "INVALID_FEES", "Provide the withdrawal fee in USDT.")
        value = values["USDT"]
        if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9]\d*)(?:\.\d+)?", value):
            raise DomainError(422, "INVALID_FEE", "Enter a valid USDT withdrawal fee.")
        atomic = 0 if value == "0" else parse_amount(value, "USDT")
        normalized = {"USDT": format_amount(atomic, "USDT")}
        normalized_reason = self._reason(reason)
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO app_settings (key, value) VALUES ('withdrawal_fee_USDT', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (normalized["USDT"],),
            )
            self._audit(connection, actor_id, "withdrawal_fees_updated", "platform", normalized_reason, request_id)
        return normalized

    def transfer(
        self,
        actor_id: str,
        recipient_id: Any,
        asset: Any,
        amount: Any,
        memo: Any,
        idempotency_key: str,
    ) -> dict[str, Any]:
        normalized_asset = self._asset(asset)
        normalized_memo = self._memo(memo)
        amount_atomic = parse_amount(amount, normalized_asset)
        if not isinstance(recipient_id, str):
            raise DomainError(422, "INVALID_RECIPIENT", "Choose an active recipient.")
        payload = {
            "recipientId": recipient_id,
            "asset": normalized_asset,
            "amountAtomic": str(amount_atomic),
            "memo": normalized_memo,
        }
        with self.database.transaction() as connection:
            replay = self._idempotent(connection, actor_id, idempotency_key, payload)
            if replay is not None:
                return replay
            recipient = connection.execute(
                "SELECT id, status FROM users WHERE id = ? AND role = 'user' AND deleted_at IS NULL",
                (recipient_id,),
            ).fetchone()
            if recipient is None or recipient["status"] != "active":
                raise DomainError(404, "RECIPIENT_NOT_FOUND", "Choose an active recipient.")
            if recipient_id == actor_id:
                raise DomainError(422, "SELF_TRANSFER", "You cannot send assets to yourself.")
            sender_account = self._account(connection, actor_id, normalized_asset, "available")
            recipient_account = self._account(
                connection, recipient_id, normalized_asset, "available"
            )
            self._ensure_funds(connection, sender_account, amount_atomic)
            transaction_id = self._post(
                connection,
                kind="transfer",
                actor_id=actor_id,
                entries=[(sender_account, -amount_atomic), (recipient_account, amount_atomic)],
                metadata={
                    "fromUserId": actor_id,
                    "toUserId": recipient_id,
                    "asset": normalized_asset,
                    "amountAtomic": str(amount_atomic),
                    "memo": normalized_memo,
                },
                idempotency_key=idempotency_key,
                payload=payload,
            )
            return self._transaction_result(connection, transaction_id)

    def withdraw(
        self,
        user_id: str,
        asset: Any,
        amount: Any,
        address: Any,
        network: Any,
        memo: Any,
        idempotency_key: str,
    ) -> dict[str, Any]:
        normalized_asset = self._asset(asset)
        amount_atomic = parse_amount(amount, normalized_asset)
        normalized_memo = self._memo(memo)
        if not isinstance(network, str) or network not in ASSET_NETWORKS[normalized_asset]:
            raise DomainError(422, "UNSUPPORTED_NETWORK", "Choose a supported network for this asset.")
        if not isinstance(address, str):
            raise DomainError(422, "INVALID_ADDRESS", "Enter a valid destination address.")
        normalized_address = address.strip()
        if network == "Bitcoin":
            valid_address = bool(
                re.fullmatch(
                    r"(?i:bc1[ac-hj-np-z02-9]{11,71})|[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
                    normalized_address,
                )
            )
        elif network == "Tron-TRC20":
            valid_address = bool(re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", normalized_address))
        else:
            valid_address = bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", normalized_address))
        if not valid_address:
            raise DomainError(422, "INVALID_ADDRESS", "Enter a valid address for the selected network.")

        with self.database.transaction() as connection:
            fee_atomic = self._withdrawal_fee_atomic(connection)
            payload = {
                "asset": normalized_asset,
                "amountAtomic": str(amount_atomic),
                "feeAtomic": str(fee_atomic),
                "address": normalized_address,
                "network": network,
                "memo": normalized_memo,
            }
            replay = self._idempotent(connection, user_id, idempotency_key, payload)
            if replay is not None:
                return replay
            eligibility = connection.execute(
                "SELECT fee_atomic, consumed_at FROM withdrawal_eligibility "
                "WHERE user_id = ? AND asset = ?",
                (user_id, "USDT"),
            ).fetchone()
            if fee_atomic > 0 and (
                eligibility is None
                or eligibility["consumed_at"] is not None
                or int(eligibility["fee_atomic"]) != fee_atomic
            ):
                raise DomainError(
                    403,
                    "WITHDRAWAL_FEE_REQUIRED",
                    "Pay the current withdrawal fee before making a withdrawal.",
                )
            available = self._account(connection, user_id, normalized_asset, "available")
            withdrawals = self._account(
                connection, None, normalized_asset, "system", "external_withdrawals"
            )
            self._ensure_funds(connection, available, amount_atomic)
            transaction_id = self._post(
                connection,
                kind="withdrawal",
                actor_id=user_id,
                entries=[
                    (available, -amount_atomic),
                    (withdrawals, amount_atomic),
                ],
                metadata={
                    "userId": user_id,
                    "asset": normalized_asset,
                    "amountAtomic": str(amount_atomic),
                    "fee": format_amount(fee_atomic, "USDT"),
                    "feeAsset": "USDT",
                    "feePaidSeparately": True,
                    "address": normalized_address,
                    "network": network,
                    "memo": normalized_memo,
                },
                idempotency_key=idempotency_key,
                payload=payload,
            )
            if fee_atomic > 0:
                connection.execute(
                    "UPDATE withdrawal_eligibility SET consumed_at = ? "
                    "WHERE user_id = ? AND asset = ? AND fee_atomic = ? AND consumed_at IS NULL",
                    (timestamp(), user_id, "USDT", str(fee_atomic)),
                )
            return self._transaction_result(connection, transaction_id)

    def create_investment(
        self,
        user_id: str,
        asset: Any,
        amount: Any,
        risk_acknowledged: Any,
        idempotency_key: str,
    ) -> dict[str, Any]:
        normalized_asset = self._asset(asset)
        amount_atomic = parse_amount(amount, normalized_asset)
        if risk_acknowledged is not True:
            raise DomainError(
                422,
                "ACKNOWLEDGEMENT_REQUIRED",
                "Acknowledge that this is an illustrative simulation.",
            )
        investment_id = opaque_id("inv")
        payload = {
            "asset": normalized_asset,
            "amountAtomic": str(amount_atomic),
            "riskAcknowledged": True,
        }
        with self.database.transaction() as connection:
            replay = self._idempotent(connection, user_id, idempotency_key, payload)
            if replay is not None:
                return replay
            available = self._account(connection, user_id, normalized_asset, "available")
            investment_account = self._account(
                connection, user_id, normalized_asset, "investment", investment_id
            )
            self._ensure_funds(connection, available, amount_atomic)
            transaction_id = self._post(
                connection,
                kind="investment",
                actor_id=user_id,
                entries=[(available, -amount_atomic), (investment_account, amount_atomic)],
                metadata={
                    "investmentId": investment_id,
                    "userId": user_id,
                    "asset": normalized_asset,
                    "amountAtomic": str(amount_atomic),
                },
                idempotency_key=idempotency_key,
                payload=payload,
            )
            created_at = timestamp()
            connection.execute(
                """
                INSERT INTO investments
                    (id, user_id, asset, principal_atomic, terms_json, cycles_completed,
                     status, transaction_id, created_at)
                VALUES (?, ?, ?, ?, ?, 0, 'active', ?, ?)
                """,
                (
                    investment_id,
                    user_id,
                    normalized_asset,
                    str(amount_atomic),
                    json.dumps(
                        {
                            "cycleDays": 7,
                            "illustrativeRateBps": 800,
                            "rulesVersion": 1,
                        },
                        separators=(",", ":"),
                    ),
                    transaction_id,
                    created_at,
                ),
            )
            return self._transaction_result(connection, transaction_id)

    def investments(self, user_id: str, admin: bool = False) -> list[dict[str, Any]]:
        query = """
            SELECT investments.*, users.email
            FROM investments JOIN users ON users.id = investments.user_id
        """
        params: tuple[Any, ...] = ()
        if not admin:
            query += " WHERE investments.user_id = ?"
            params = (user_id,)
        query += " ORDER BY investments.created_at DESC LIMIT 500"
        connection = self.database.connect()
        try:
            rows = connection.execute(query, params).fetchall()
            return [
                {
                    "id": row["id"],
                    "userId": row["user_id"],
                    "email": row["email"] if admin else None,
                    "asset": row["asset"],
                    "principal": format_amount(row["principal_atomic"], row["asset"]),
                    "terms": json.loads(row["terms_json"]),
                    "cyclesCompleted": row["cycles_completed"],
                    "status": row["status"],
                    "createdAt": row["created_at"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def transactions(
        self,
        user_id: str,
        admin: bool = False,
        kind: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        limit = min(max(limit, 1), 200)
        query = """
            SELECT DISTINCT journal_transactions.*
            FROM journal_transactions
        """
        params: list[Any] = []
        if not admin:
            query += """
                WHERE EXISTS (
                    SELECT 1 FROM journal_entries
                    JOIN accounts ON accounts.id = journal_entries.account_id
                    WHERE journal_entries.transaction_id = journal_transactions.id
                      AND accounts.owner_id = ?
                )
            """
            params.append(user_id)
        if kind:
            query += " AND " if "WHERE" in query else " WHERE "
            query += "journal_transactions.kind = ?"
            params.append(kind)
        query += " ORDER BY journal_transactions.created_at DESC LIMIT ?"
        params.append(limit)
        connection = self.database.connect()
        try:
            rows = connection.execute(query, params).fetchall()
            return [self._transaction_result(connection, row["id"]) for row in rows]
        finally:
            connection.close()

    def admin_users(self, search: Any = "") -> list[dict[str, Any]]:
        if not isinstance(search, str) or len(search) > 100:
            raise DomainError(422, "INVALID_SEARCH", "Search text is too long.")
        term = f"%{search.strip()}%"
        connection = self.database.connect()
        try:
            users = connection.execute(
                """
                SELECT id, email, name, role, status, created_at
                FROM users
                WHERE role = 'user' AND deleted_at IS NULL
                  AND (name LIKE ? OR email LIKE ? OR id LIKE ?)
                ORDER BY created_at DESC LIMIT 200
                """,
                (term, term, term),
            ).fetchall()
            result = []
            for user in users:
                balances = connection.execute(
                    """
                    SELECT accounts.asset, balance_projection.amount_atomic
                    FROM accounts JOIN balance_projection
                      ON balance_projection.account_id = accounts.id
                    WHERE accounts.owner_id = ? AND accounts.bucket = 'available'
                    """,
                    (user["id"],),
                ).fetchall()
                result.append(
                    {
                        "id": user["id"],
                        "email": user["email"],
                        "name": user["name"],
                        "role": user["role"],
                        "status": user["status"],
                        "createdAt": user["created_at"],
                        "balances": {
                            row["asset"]: format_amount(row["amount_atomic"], row["asset"])
                            for row in balances
                        },
                    }
                )
            return result
        finally:
            connection.close()

    def user_directory(self) -> list[dict[str, str]]:
        connection = self.database.connect()
        try:
            rows = connection.execute(
                """
                SELECT id, email, name, status
                FROM users
                WHERE role = 'user' AND status = 'active' AND deleted_at IS NULL
                ORDER BY name
                LIMIT 200
                """
            ).fetchall()
            return [
                {"id": row["id"], "email": row["email"], "name": row["name"]}
                for row in rows
            ]
        finally:
            connection.close()

    def admin_credit(
        self,
        actor_id: str,
        user_id: Any,
        asset: Any,
        amount: Any,
        reason: Any,
        idempotency_key: str,
        request_id: str,
    ) -> dict[str, Any]:
        normalized_asset = self._asset(asset)
        amount_atomic = parse_amount(amount, normalized_asset)
        normalized_reason = self._reason(reason)
        if not isinstance(user_id, str):
            raise DomainError(422, "INVALID_USER", "Choose an active user.")
        payload = {
            "userId": user_id,
            "asset": normalized_asset,
            "amountAtomic": str(amount_atomic),
            "reason": normalized_reason,
        }
        with self.database.transaction() as connection:
            replay = self._idempotent(connection, actor_id, idempotency_key, payload)
            if replay is not None:
                return replay
            user = connection.execute(
                "SELECT id, status FROM users WHERE id = ? AND role = 'user' AND deleted_at IS NULL",
                (user_id,),
            ).fetchone()
            if user is None or user["status"] != "active":
                raise DomainError(404, "USER_NOT_FOUND", "Choose an active user.")
            user_account = self._account(connection, user_id, normalized_asset, "available")
            issuance = self._account(connection, None, normalized_asset, "system", "issuance")
            transaction_id = self._post(
                connection,
                kind="admin_demo_credit",
                actor_id=actor_id,
                entries=[(issuance, -amount_atomic), (user_account, amount_atomic)],
                metadata={
                    "userId": user_id,
                    "asset": normalized_asset,
                    "amountAtomic": str(amount_atomic),
                    "reason": normalized_reason,
                    "simulated": True,
                },
                idempotency_key=idempotency_key,
                payload=payload,
            )
            self._audit(
                connection,
                actor_id,
                "admin_demo_credit",
                user_id,
                normalized_reason,
                request_id,
            )
            return self._transaction_result(connection, transaction_id)

    def update_deposit_address(
        self,
        actor_id: str,
        asset: Any,
        network: Any,
        address: Any,
        enabled: Any,
        reason: Any,
        request_id: str,
    ) -> dict[str, Any]:
        normalized_asset = self._asset(asset)
        if not isinstance(network, str) or network not in ASSET_NETWORKS[normalized_asset]:
            raise DomainError(422, "UNSUPPORTED_NETWORK", "Choose a supported asset network.")
        address_pattern = DEPOSIT_ADDRESS_PATTERNS[network]
        if (
            not isinstance(address, str)
            or not address
            or len(address) > 90
            or (not DEMO_ADDRESS_RE.fullmatch(address) and not address_pattern.fullmatch(address))
        ):
            raise DomainError(
                422,
                "INVALID_DEPOSIT_ADDRESS",
                f"Enter a valid {network} address or a DEMO- placeholder.",
            )
        if not isinstance(enabled, bool):
            raise DomainError(422, "INVALID_STATUS", "Enabled must be a boolean.")
        normalized_reason = self._reason(reason)
        updated_at = timestamp()
        with self.database.transaction() as connection:
            connection.execute(
                """
                INSERT INTO deposit_addresses (asset, network, address, enabled, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset, network) DO UPDATE SET
                    address = excluded.address,
                    enabled = excluded.enabled,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
                """,
                (normalized_asset, network, address, int(enabled), actor_id, updated_at),
            )
            self._audit(
                connection,
                actor_id,
                "deposit_address_updated",
                f"{normalized_asset}:{network}",
                normalized_reason,
                request_id,
            )
        return {
            "asset": normalized_asset,
            "network": network,
            "address": address,
            "enabled": enabled,
            "updatedAt": updated_at,
        }

    def set_user_status(
        self,
        actor_id: str,
        user_id: str,
        status: Any,
        reason: Any,
        request_id: str,
    ) -> dict[str, str]:
        if status not in ("active", "suspended"):
            raise DomainError(422, "INVALID_STATUS", "Status must be active or suspended.")
        normalized_reason = self._reason(reason)
        with self.database.transaction() as connection:
            user = connection.execute(
                "SELECT id, status FROM users WHERE id = ? AND role = 'user' AND deleted_at IS NULL",
                (user_id,),
            ).fetchone()
            if user is None:
                raise DomainError(404, "USER_NOT_FOUND", "User was not found.")
            connection.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))
            if status == "suspended":
                connection.execute(
                    "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                    (timestamp(), user_id),
                )
            self._audit(connection, actor_id, "user_status_updated", user_id, normalized_reason, request_id)
        return {"userId": user_id, "status": status}

    def delete_user(
        self,
        actor_id: str,
        user_id: str,
        reason: Any,
        request_id: str,
    ) -> dict[str, str]:
        normalized_reason = self._reason(reason)
        deleted_at = timestamp()
        with self.database.transaction() as connection:
            user = connection.execute(
                "SELECT id FROM users WHERE id = ? AND role = 'user' AND deleted_at IS NULL",
                (user_id,),
            ).fetchone()
            if user is None:
                raise DomainError(404, "USER_NOT_FOUND", "User was not found.")
            connection.execute(
                "UPDATE users SET status = 'suspended', deleted_at = ?, "
                "email = ?, name = 'Deleted user', password_hash = ? WHERE id = ?",
                (
                    deleted_at,
                    f"deleted+{user_id}@deleted.invalid",
                    secrets.token_hex(32),
                    user_id,
                ),
            )
            connection.execute(
                "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                (deleted_at, user_id),
            )
            self._audit(
                connection,
                actor_id,
                "user_deleted",
                user_id,
                normalized_reason,
                request_id,
            )
        return {"userId": user_id, "status": "deleted"}

    def _create_user_accounts(
        self,
        connection: DatabaseConnection,
        user_id: str,
        created_at: str,
    ) -> None:
        for symbol, _, _ in ASSETS:
            self._account(connection, user_id, symbol, "available", created_at=created_at)

    def _new_session(self, user_id: str) -> dict[str, str]:
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(24)
        return {
            "id": opaque_id("ses"),
            "user_id": user_id,
            "token": token,
            "token_hash": hashlib.sha256(token.encode("ascii")).hexdigest(),
            "csrf_token": csrf_token,
            "expires_at": timestamp(utc_now() + timedelta(days=self.session_days)),
            "created_at": timestamp(),
        }

    @staticmethod
    def _insert_session(connection: DatabaseConnection, session: dict[str, str]) -> None:
        connection.execute(
            """
            INSERT INTO sessions (id, user_id, token_hash, csrf_token, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session["id"],
                session["user_id"],
                session["token_hash"],
                session["csrf_token"],
                session["expires_at"],
                session["created_at"],
            ),
        )

    @staticmethod
    def _validate_password(password: Any, admin: bool = False) -> None:
        minimum = 16 if admin else PASSWORD_MIN_LENGTH
        if not isinstance(password, str) or not minimum <= len(password) <= 256:
            raise DomainError(
                422,
                "INVALID_PASSWORD",
                f"Password must be between {minimum} and 256 characters.",
            )

    @staticmethod
    def _public_user(
        user_id: str,
        email: str,
        name: str,
        role: str,
        status: str,
        created_at: str,
    ) -> dict[str, str]:
        return {
            "id": user_id,
            "email": email,
            "name": name,
            "role": role,
            "status": status,
            "createdAt": created_at,
        }

    @staticmethod
    def _asset(value: Any) -> str:
        if not isinstance(value, str) or value not in ASSET_DECIMALS:
            raise DomainError(422, "UNSUPPORTED_ASSET", "Choose a supported asset.")
        return value

    @staticmethod
    def _memo(value: Any) -> str:
        if value is None:
            return ""
        if not isinstance(value, str) or len(value) > 160:
            raise DomainError(422, "INVALID_MEMO", "Memo must be at most 160 characters.")
        return value.strip()

    @staticmethod
    def _reason(value: Any) -> str:
        if not isinstance(value, str) or not 3 <= len(value.strip()) <= 240:
            raise DomainError(422, "REASON_REQUIRED", "Provide a reason between 3 and 240 characters.")
        return value.strip()

    @staticmethod
    def _account(
        connection: DatabaseConnection,
        owner_id: str | None,
        asset: str,
        bucket: str,
        reference: str = "",
        created_at: str | None = None,
    ) -> str:
        row = connection.execute(
            """
            SELECT id FROM accounts
            WHERE owner_id IS ? AND asset = ? AND bucket = ? AND reference = ?
            """,
            (owner_id, asset, bucket, reference),
        ).fetchone()
        if row is not None:
            return row["id"]
        account_id = opaque_id("acct")
        connection.execute(
            """
            INSERT INTO accounts (id, owner_id, asset, bucket, reference, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (account_id, owner_id, asset, bucket, reference, created_at or timestamp()),
        )
        connection.execute(
            "INSERT INTO balance_projection (account_id, amount_atomic) VALUES (?, '0')",
            (account_id,),
        )
        return account_id

    @staticmethod
    def _ensure_funds(
        connection: DatabaseConnection,
        account_id: str,
        amount_atomic: int,
    ) -> None:
        row = connection.execute(
            "SELECT amount_atomic FROM balance_projection WHERE account_id = ?",
            (account_id,),
        ).fetchone()
        if row is None or int(row["amount_atomic"]) < amount_atomic:
            raise DomainError(409, "INSUFFICIENT_BALANCE", "Available demo balance is insufficient.")

    def _post(
        self,
        connection: DatabaseConnection,
        kind: str,
        actor_id: str,
        entries: list[tuple[str, int]],
        metadata: dict[str, Any],
        idempotency_key: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> str:
        totals: dict[str, int] = {}
        for account_id, amount_atomic in entries:
            account = connection.execute(
                "SELECT asset FROM accounts WHERE id = ?",
                (account_id,),
            ).fetchone()
            if account is None:
                raise RuntimeError("Ledger posting references a missing account.")
            totals[account["asset"]] = totals.get(account["asset"], 0) + amount_atomic
        if not entries or any(total != 0 for total in totals.values()):
            raise RuntimeError("Ledger transaction is not balanced per asset.")

        transaction_id = opaque_id("txn")
        reference = f"NX-{uuid.uuid4().hex[:16].upper()}"
        connection.execute(
            """
            INSERT INTO journal_transactions
                (id, reference, kind, status, actor_id, idempotency_key, payload_hash,
                 metadata_json, created_at)
            VALUES (?, ?, ?, 'completed_simulated', ?, ?, ?, ?, ?)
            """,
            (
                transaction_id,
                reference,
                kind,
                actor_id,
                idempotency_key,
                payload_digest(payload) if payload is not None else None,
                json.dumps(metadata, separators=(",", ":"), sort_keys=True),
                timestamp(),
            ),
        )
        account_totals: dict[str, int] = {}
        for account_id, amount_atomic in entries:
            entry_id = opaque_id("ent")
            connection.execute(
                """
                INSERT INTO journal_entries (id, transaction_id, account_id, amount_atomic)
                VALUES (?, ?, ?, ?)
                """,
                (entry_id, transaction_id, account_id, str(amount_atomic)),
            )
            account_totals[account_id] = account_totals.get(account_id, 0) + amount_atomic
        for account_id, delta in account_totals.items():
            row = connection.execute(
                "SELECT amount_atomic FROM balance_projection WHERE account_id = ?",
                (account_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("Ledger projection is missing an account.")
            updated = int(row["amount_atomic"]) + delta
            connection.execute(
                "UPDATE balance_projection SET amount_atomic = ? WHERE account_id = ?",
                (str(updated), account_id),
            )
        return transaction_id

    def _idempotent(
        self,
        connection: DatabaseConnection,
        actor_id: str,
        key: str,
        payload: dict[str, Any],
    ) -> dict[str, Any] | None:
        if not isinstance(key, str) or not 8 <= len(key) <= 128:
            raise DomainError(
                400,
                "IDEMPOTENCY_KEY_REQUIRED",
                "Provide an Idempotency-Key between 8 and 128 characters.",
            )
        existing = connection.execute(
            """
            SELECT id, payload_hash FROM journal_transactions
            WHERE actor_id = ? AND idempotency_key = ?
            """,
            (actor_id, key),
        ).fetchone()
        if existing is None:
            return None
        if not hmac.compare_digest(existing["payload_hash"] or "", payload_digest(payload)):
            raise DomainError(
                409,
                "IDEMPOTENCY_CONFLICT",
                "This idempotency key was already used with a different request.",
            )
        return self._transaction_result(connection, existing["id"])

    @staticmethod
    def _transaction_result(
        connection: DatabaseConnection,
        transaction_id: str,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM journal_transactions WHERE id = ?",
            (transaction_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("Journal transaction disappeared during read.")
        metadata = json.loads(row["metadata_json"])
        asset = metadata.get("asset")
        amount = (
            format_amount(metadata["amountAtomic"], asset)
            if asset in ASSET_DECIMALS and "amountAtomic" in metadata
            else None
        )
        return {
            "id": row["id"],
            "reference": row["reference"],
            "type": row["kind"],
            "status": row["status"],
            "asset": asset,
            "amount": amount,
            "metadata": metadata,
            "createdAt": row["created_at"],
        }

    @staticmethod
    def _audit(
        connection: DatabaseConnection,
        actor_id: str,
        action: str,
        target: str,
        reason: str,
        request_id: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO audit_events (id, actor_id, action, target, reason, request_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (opaque_id("aud"), actor_id, action, target, reason, request_id, timestamp()),
        )
