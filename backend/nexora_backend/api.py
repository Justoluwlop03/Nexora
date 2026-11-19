from __future__ import annotations

import json
import hmac
import logging
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .config import Config
from .database import Database
from .service import BackendService, DomainError

LOGGER = logging.getLogger("nexora.api")
MAX_BODY_BYTES = 64 * 1024
SESSION_COOKIE = "nexora_session"
CSRF_COOKIE = "nexora_csrf"


class AuthRateLimiter:
    def __init__(self, maximum: int = 10, window_seconds: int = 60) -> None:
        self.maximum = maximum
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] >= self.window_seconds:
                events.popleft()
            if len(events) >= self.maximum:
                raise DomainError(
                    429,
                    "RATE_LIMITED",
                    "Too many authentication attempts. Try again shortly.",
                )
            events.append(now)


class NexoraHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: Config, database: Database) -> None:
        self.config = config
        self.database = database
        self.service = BackendService(database, config.session_days)
        self.auth_limiter = AuthRateLimiter()
        super().__init__(address, NexoraRequestHandler)


class NexoraRequestHandler(BaseHTTPRequestHandler):
    server: NexoraHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: Any) -> None:
        path = urlsplit(self.path).path
        LOGGER.info("%s %s from %s", self.command, path, self.client_address[0])

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin", "").rstrip("/")
        if not origin or origin != self.server.config.frontend_origin:
            self._send_error(
                DomainError(403, "ORIGIN_INVALID", "Request origin is not allowed."),
                self._request_id(),
            )
            return
        self.send_response(204)
        self._add_cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, X-CSRF-Token, Idempotency-Key",
        )
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _dispatch(self, method: str) -> None:
        request_id = self._request_id()
        try:
            if self._content_length() > MAX_BODY_BYTES:
                raise DomainError(413, "BODY_TOO_LARGE", "Request body exceeds 64 KiB.")
            if self.headers.get("Transfer-Encoding"):
                self.close_connection = True
                raise DomainError(400, "TRANSFER_ENCODING_UNSUPPORTED", "Chunked requests are not supported.")
            if method in {"POST", "PUT"}:
                self._validate_origin()

            parsed = urlsplit(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query, keep_blank_values=False)
            if method == "GET" and path in {"/health", "/api/v1/health"}:
                self.server.database.check()
                self._send_json(200, {"data": {"status": "ok"}, "requestId": request_id})
                return

            if method == "POST" and path == "/api/v1/auth/register":
                self.server.auth_limiter.check(self.client_address[0])
                body = self._read_json()
                user, token, csrf = self.server.service.register(
                    body.get("name"),
                    body.get("email"),
                    body.get("password"),
                )
                self._set_session_cookies(token, csrf)
                self._send_json(
                    201,
                    {
                        "data": {"user": user, "csrfToken": csrf},
                        "requestId": request_id,
                    },
                )
                return

            if method == "POST" and path == "/api/v1/auth/login":
                self.server.auth_limiter.check(self.client_address[0])
                body = self._read_json()
                user, token, csrf = self.server.service.login(
                    body.get("email"),
                    body.get("password"),
                )
                self._set_session_cookies(token, csrf)
                self._send_json(
                    200,
                    {
                        "data": {"user": user, "csrfToken": csrf},
                        "requestId": request_id,
                    },
                )
                return

            if method == "POST" and path == "/api/v1/auth/logout":
                user, _csrf = self._authenticated(write=True)
                del user
                token = self._cookies().get(SESSION_COOKIE)
                if token:
                    self.server.service.logout(token)
                self._clear_session_cookies()
                self._send_json(200, {"data": {"loggedOut": True}, "requestId": request_id})
                return

            if method == "GET" and path == "/api/v1/assets":
                self._send_json(
                    200,
                    {"data": self.server.service.assets(), "requestId": request_id},
                )
                return

            if method == "GET" and path == "/api/v1/deposit-addresses":
                self._authenticated()
                self._send_json(
                    200,
                    {"data": self.server.service.deposit_addresses(), "requestId": request_id},
                )
                return

            if method == "GET" and path == "/api/v1/me":
                user, csrf = self._authenticated()
                self._send_json(
                    200,
                    {
                        "data": {"user": user, "csrfToken": csrf},
                        "requestId": request_id,
                    },
                )
                return

            if method == "GET" and path == "/api/v1/users":
                self._authenticated()
                self._send_json(
                    200,
                    {"data": self.server.service.user_directory(), "requestId": request_id},
                )
                return

            if method == "GET" and path == "/api/v1/withdrawal-fees":
                self._authenticated()
                self._send_json(200, {"data": self.server.service.withdrawal_fees(), "requestId": request_id})
                return

            if method == "GET" and path == "/api/v1/withdrawal-eligibility":
                user, _csrf = self._authenticated()
                self._send_json(
                    200,
                    {"data": self.server.service.withdrawal_eligibility(user["id"]), "requestId": request_id},
                )
                return

            if method == "POST" and path == "/api/v1/withdrawal-fees/pay":
                user, _csrf = self._authenticated(write=True)
                if user["role"] != "user":
                    raise DomainError(403, "FORBIDDEN", "Only user accounts can pay withdrawal fees.")
                body = self._read_json()
                result = self.server.service.pay_withdrawal_fee(
                    user["id"],
                    self.headers.get("Idempotency-Key", ""),
                )
                self._send_json(201, {"data": result, "requestId": request_id})
                return

            if method == "GET" and path == "/api/v1/wallets/me/balances":
                user, _csrf = self._authenticated()
                self._send_json(
                    200,
                    {"data": self.server.service.balances(user["id"]), "requestId": request_id},
                )
                return

            if method == "GET" and path == "/api/v1/transactions":
                user, _csrf = self._authenticated()
                self._send_json(
                    200,
                    {
                        "data": self.server.service.transactions(
                            user["id"],
                            kind=self._one(query, "type"),
                            limit=self._limit(query),
                        ),
                        "requestId": request_id,
                    },
                )
                return

            if method == "POST" and path == "/api/v1/transfers":
                user, _csrf = self._authenticated(write=True)
                if user["role"] != "admin":
                    raise DomainError(
                        403,
                        "FORBIDDEN",
                        "User to user asset transfers are unavailable.",
                    )
                body = self._read_json()
                result = self.server.service.transfer(
                    user["id"],
                    body.get("recipientId"),
                    body.get("asset"),
                    body.get("amount"),
                    body.get("memo"),
                    self.headers.get("Idempotency-Key", ""),
                )
                self._send_json(201, {"data": result, "requestId": request_id})
                return

            if method == "POST" and path == "/api/v1/withdrawals":
                user, _csrf = self._authenticated(write=True)
                if user["role"] != "user":
                    raise DomainError(403, "FORBIDDEN", "Only user accounts can request withdrawals.")
                body = self._read_json()
                result = self.server.service.withdraw(
                    user["id"],
                    body.get("asset"),
                    body.get("amount"),
                    body.get("address"),
                    body.get("network"),
                    body.get("memo"),
                    self.headers.get("Idempotency-Key", ""),
                )
                self._send_json(201, {"data": result, "requestId": request_id})
                return

            if method == "GET" and path == "/api/v1/investments":
                user, _csrf = self._authenticated()
                self._send_json(
                    200,
                    {"data": self.server.service.investments(user["id"]), "requestId": request_id},
                )
                return

            if method == "POST" and path == "/api/v1/investments":
                user, _csrf = self._authenticated(write=True)
                body = self._read_json()
                result = self.server.service.create_investment(
                    user["id"],
                    body.get("asset"),
                    body.get("amount"),
                    body.get("riskAcknowledged"),
                    self.headers.get("Idempotency-Key", ""),
                )
                self._send_json(201, {"data": result, "requestId": request_id})
                return

            if method == "PUT" and path == "/api/v1/admin/withdrawal-fees":
                admin = self._require_admin(write=True)
                body = self._read_json()
                result = self.server.service.update_withdrawal_fees(
                    admin["id"], body.get("fees"), body.get("reason"), request_id
                )
                self._send_json(200, {"data": result, "requestId": request_id})
                return

            if method == "GET" and path.startswith("/api/v1/admin/"):
                admin = self._require_admin()
                if path == "/api/v1/admin/users":
                    self._send_json(
                        200,
                        {
                            "data": self.server.service.admin_users(self._one(query, "search", "")),
                            "requestId": request_id,
                        },
                    )
                    return
                if path == "/api/v1/admin/transactions":
                    self._send_json(
                        200,
                        {
                            "data": self.server.service.transactions(
                                admin["id"],
                                admin=True,
                                kind=self._one(query, "type"),
                                limit=self._limit(query),
                            ),
                            "requestId": request_id,
                        },
                    )
                    return
                if path == "/api/v1/admin/investments":
                    self._send_json(
                        200,
                        {
                            "data": self.server.service.investments(admin["id"], admin=True),
                            "requestId": request_id,
                        },
                    )
                    return
                if path == "/api/v1/admin/deposit-addresses":
                    self._send_json(
                        200,
                        {
                            "data": self.server.service.admin_deposit_addresses(),
                            "requestId": request_id,
                        },
                    )
                    return

            if method == "POST" and path == "/api/v1/admin/account/credentials":
                admin = self._require_admin(write=True)
                self.server.auth_limiter.check(self.client_address[0])
                body = self._read_json()
                user, token, csrf = self.server.service.update_admin_credentials(
                    admin["id"],
                    body.get("currentPassword"),
                    body.get("email"),
                    body.get("newPassword"),
                    request_id,
                )
                self._set_session_cookies(token, csrf)
                self._send_json(
                    200,
                    {"data": {"user": user, "csrfToken": csrf}, "requestId": request_id},
                )
                return

            if method == "POST" and path == "/api/v1/admin/wallet-credits":
                admin = self._require_admin(write=True)
                body = self._read_json()
                result = self.server.service.admin_credit(
                    admin["id"],
                    body.get("userId"),
                    body.get("asset"),
                    body.get("amount"),
                    body.get("reason"),
                    self.headers.get("Idempotency-Key", ""),
                    request_id,
                )
                self._send_json(201, {"data": result, "requestId": request_id})
                return

            address_match = re.fullmatch(
                r"/api/v1/admin/deposit-addresses/([A-Z0-9]+)/([A-Za-z0-9-]+)",
                path,
            )
            if method == "PUT" and address_match:
                admin = self._require_admin(write=True)
                body = self._read_json()
                result = self.server.service.update_deposit_address(
                    admin["id"],
                    address_match.group(1),
                    address_match.group(2),
                    body.get("address"),
                    body.get("enabled"),
                    body.get("reason"),
                    request_id,
                )
                self._send_json(200, {"data": result, "requestId": request_id})
                return

            delete_user_match = re.fullmatch(r"/api/v1/admin/users/([^/]+)/delete", path)
            if method == "POST" and delete_user_match:
                admin = self._require_admin(write=True)
                body = self._read_json()
                result = self.server.service.delete_user(
                    admin["id"],
                    delete_user_match.group(1),
                    body.get("reason"),
                    request_id,
                )
                self._send_json(200, {"data": result, "requestId": request_id})
                return

            status_match = re.fullmatch(r"/api/v1/admin/users/([^/]+)/status", path)
            if method == "POST" and status_match:
                admin = self._require_admin(write=True)
                body = self._read_json()
                result = self.server.service.set_user_status(
                    admin["id"],
                    status_match.group(1),
                    body.get("status"),
                    body.get("reason"),
                    request_id,
                )
                self._send_json(200, {"data": result, "requestId": request_id})
                return

            raise DomainError(404, "NOT_FOUND", "API route was not found.")
        except DomainError as exc:
            self._send_error(exc, request_id)
        except (BrokenPipeError, ConnectionResetError):
            LOGGER.info("Client disconnected during request %s", request_id)
        except Exception:
            LOGGER.exception("Unhandled backend error for request %s", request_id)
            self._send_error(
                DomainError(500, "INTERNAL_ERROR", "An unexpected server error occurred."),
                request_id,
            )

    def _authenticated(self, write: bool = False) -> tuple[dict[str, Any], str]:
        cookies = self._cookies()
        user, csrf = self.server.service.authenticate(cookies.get(SESSION_COOKIE))
        if write:
            provided = self.headers.get("X-CSRF-Token", "")
            cookie_token = cookies.get(CSRF_COOKIE, "")
            if (
                not provided
                or not cookie_token
                or not secrets_compare(provided, csrf)
                or not secrets_compare(cookie_token, csrf)
            ):
                raise DomainError(403, "CSRF_INVALID", "CSRF validation failed.")
        return user, csrf

    def _require_admin(self, write: bool = False) -> dict[str, Any]:
        user, _csrf = self._authenticated(write=write)
        if user["role"] != "admin":
            raise DomainError(403, "FORBIDDEN", "Administrator access is required.")
        return user

    def _validate_origin(self) -> None:
        origin = self.headers.get("Origin")
        if not origin:
            return
        try:
            origin_host = urlsplit(origin).netloc.lower()
        except ValueError as exc:
            raise DomainError(403, "ORIGIN_INVALID", "Request origin is not allowed.") from exc
        if (
            not origin_host
            or (
                origin_host != self.headers.get("Host", "").lower()
                and origin.rstrip("/") != self.server.config.frontend_origin
            )
        ):
            raise DomainError(403, "ORIGIN_INVALID", "Request origin is not allowed.")

    def _read_json(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise DomainError(415, "JSON_REQUIRED", "Send a JSON request body.")
        length = self._content_length()
        if length > MAX_BODY_BYTES:
            raise DomainError(413, "BODY_TOO_LARGE", "Request body exceeds 64 KiB.")
        try:
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DomainError(400, "INVALID_JSON", "Request body must be valid JSON.") from exc
        if not isinstance(payload, dict):
            raise DomainError(400, "INVALID_JSON", "Request body must be a JSON object.")
        return payload

    def _content_length(self) -> int:
        raw = self.headers.get("Content-Length", "0")
        try:
            length = int(raw)
        except ValueError as exc:
            raise DomainError(400, "INVALID_LENGTH", "Content-Length must be an integer.") from exc
        if length < 0:
            raise DomainError(400, "INVALID_LENGTH", "Content-Length cannot be negative.")
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            raise DomainError(413, "BODY_TOO_LARGE", "Request body exceeds 64 KiB.")
        return length

    def _cookies(self) -> dict[str, str]:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError as exc:
            raise DomainError(400, "INVALID_COOKIE", "Request cookie is invalid.") from exc
        return {key: morsel.value for key, morsel in cookie.items()}

    def _set_session_cookies(self, token: str, csrf: str) -> None:
        secure = "; Secure" if self.server.config.secure_cookies else ""
        max_age = self.server.config.session_days * 24 * 60 * 60
        self._pending_cookies = [
            f"{SESSION_COOKIE}={token}; Path=/api/v1; HttpOnly; SameSite={self.server.config.cookie_samesite}; Max-Age={max_age}{secure}",
            f"{CSRF_COOKIE}={csrf}; Path=/api/v1; SameSite={self.server.config.cookie_samesite}; Max-Age={max_age}{secure}",
        ]

    def _clear_session_cookies(self) -> None:
        secure = "; Secure" if self.server.config.secure_cookies else ""
        self._pending_cookies = [
            f"{SESSION_COOKIE}=; Path=/api/v1; HttpOnly; SameSite={self.server.config.cookie_samesite}; Max-Age=0{secure}",
            f"{CSRF_COOKIE}=; Path=/api/v1; SameSite={self.server.config.cookie_samesite}; Max-Age=0{secure}",
        ]

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self._add_cors_headers()
        for cookie in getattr(self, "_pending_cookies", []):
            self.send_header("Set-Cookie", cookie)
        self._pending_cookies = []
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, error: DomainError, request_id: str) -> None:
        self._send_json(
            error.status,
            {
                "error": {"code": error.code, "message": error.message},
                "requestId": request_id,
            },
        )

    def _add_cors_headers(self) -> None:
        origin = self.headers.get("Origin", "").rstrip("/")
        if origin and origin == self.server.config.frontend_origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")

    @staticmethod
    def _one(query: dict[str, list[str]], key: str, default: str | None = None) -> str | None:
        values = query.get(key, [])
        return values[0] if values else default

    def _limit(self, query: dict[str, list[str]]) -> int:
        raw = self._one(query, "limit", "100")
        try:
            limit = int(raw or "100")
        except ValueError as exc:
            raise DomainError(422, "INVALID_LIMIT", "Limit must be an integer.") from exc
        return min(max(limit, 1), 200)

    @staticmethod
    def _request_id() -> str:
        return uuid.uuid4().hex


def secrets_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def serve(config: Config) -> None:
    database = Database(config.database_path, config.database_url)
    database.initialize()
    server = NexoraHTTPServer((config.host, config.port), config, database)
    LOGGER.info(
        "Nexora backend listening on http://%s:%s (frontend origin: %s)",
        config.host,
        config.port,
        config.frontend_origin or "same-origin only",
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Stopping Nexora backend.")
    finally:
        server.server_close()


__all__ = ["NexoraHTTPServer", "serve"]
