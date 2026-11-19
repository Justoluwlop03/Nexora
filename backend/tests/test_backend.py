from __future__ import annotations

import http.cookiejar
import json
import os
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

from nexora_backend.api import NexoraHTTPServer
from nexora_backend.config import Config
from nexora_backend.database import Database
from nexora_backend.service import BackendService, DomainError, format_amount, parse_amount


ADMIN_EMAIL = "admin@example.test"
ADMIN_PASSWORD = "correct horse battery staple 2026"
USER_PASSWORD = "a secure demo password 2026"


class ConfigTests(unittest.TestCase):
    def test_default_frontend_origin_matches_local_vite(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = Config.from_environment()
        self.assertEqual(config.frontend_origin, "http://localhost:5173")

    def test_postgres_url_environment_selects_postgres_without_exposing_a_path(self) -> None:
        database_url = "postgresql://user:password@localhost:5432/nexora"
        with patch.dict(os.environ, {"NEXORA_DATABASE_URL": database_url}, clear=True):
            config = Config.from_environment()
        self.assertEqual(config.database_url, database_url)
        self.assertEqual(config.database_path.name, "nexora.sqlite3")

    def test_database_url_takes_precedence_over_sqlite_path(self) -> None:
        database_url = "postgresql://user:password@localhost:5432/nexora"
        with patch.dict(
            os.environ,
            {
                "NEXORA_DATABASE_URL": database_url,
                "NEXORA_DATABASE": "ignored.sqlite3",
            },
            clear=True,
        ):
            config = Config.from_environment()
        self.assertEqual(config.database_url, database_url)
        self.assertNotEqual(config.database_path, Path("ignored.sqlite3"))

    def test_postgres_url_is_also_supported_in_database_setting(self) -> None:
        database_url = "postgresql://user:password@localhost:5432/nexora"
        with patch.dict(os.environ, {"NEXORA_DATABASE": database_url}, clear=True):
            config = Config.from_environment()
        self.assertEqual(config.database_url, database_url)


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        database = Database(Path(self.temp_dir.name) / "nexora.sqlite3")
        database.initialize()
        self.service = BackendService(database)
        self.admin = self.service.create_admin(ADMIN_EMAIL, ADMIN_PASSWORD)
        self.alice, self.alice_token, _ = self.service.register(
            "Alice Example", "alice@example.test", USER_PASSWORD
        )
        self.bob, self.bob_token, _ = self.service.register(
            "Bob Example", "bob@example.test", USER_PASSWORD
        )
        self.database = database

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_registration_creates_demo_balance_and_secure_session(self) -> None:
        balances = {item["asset"]: item for item in self.service.balances(self.alice["id"])}
        self.assertEqual(balances["USDC"]["available"], "100")
        self.assertEqual(self.service.authenticate(self.alice_token)[0]["id"], self.alice["id"])
        self.assertNotIn("password", self.alice)
        with closing(self.database.connect()) as connection:
            row = connection.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (self.alice["id"],),
            ).fetchone()
        self.assertTrue(row["password_hash"].startswith("pbkdf2_sha256$"))

    def test_atomic_transfer_is_idempotent_and_visible_to_both_users(self) -> None:
        key = "transfer-once-0001"
        result = self.service.transfer(
            self.alice["id"], self.bob["id"], "USDC", "25.50", "test transfer", key
        )
        replay = self.service.transfer(
            self.alice["id"], self.bob["id"], "USDC", "25.50", "test transfer", key
        )
        self.assertEqual(result["id"], replay["id"])
        self.assertEqual(result["reference"], replay["reference"])
        alice_balances = {x["asset"]: x for x in self.service.balances(self.alice["id"])}
        bob_balances = {x["asset"]: x for x in self.service.balances(self.bob["id"])}
        self.assertEqual(alice_balances["USDC"]["available"], "74.5")
        self.assertEqual(bob_balances["USDC"]["available"], "125.5")
        self.assertEqual(len(self.service.transactions(self.alice["id"])), 2)
        self.assertEqual(len(self.service.transactions(self.bob["id"])), 2)

        with self.assertRaises(DomainError) as raised:
            self.service.transfer(
                self.alice["id"], self.bob["id"], "USDC", "24", "different", key
            )
        self.assertEqual(raised.exception.code, "IDEMPOTENCY_CONFLICT")

    def test_transfer_validates_balance_recipient_and_asset_precision(self) -> None:
        with self.assertRaises(DomainError) as raised:
            self.service.transfer(
                self.alice["id"], self.bob["id"], "USDC", "101", "", "transfer-funds-01"
            )
        self.assertEqual(raised.exception.code, "INSUFFICIENT_BALANCE")
        with self.assertRaises(DomainError) as raised:
            self.service.transfer(
                self.alice["id"], self.alice["id"], "USDC", "1", "", "transfer-self-0001"
            )
        self.assertEqual(raised.exception.code, "SELF_TRANSFER")
        with self.assertRaises(DomainError) as raised:
            parse_amount("0.0000001", "USDC")
        self.assertEqual(raised.exception.code, "INVALID_PRECISION")

    def test_investment_moves_demo_principal_without_crediting_returns(self) -> None:
        result = self.service.create_investment(
            self.alice["id"], "USDC", "40", True, "investment-once-001"
        )
        self.assertEqual(result["type"], "investment")
        balances = {x["asset"]: x for x in self.service.balances(self.alice["id"])}
        self.assertEqual(balances["USDC"]["available"], "60")
        self.assertEqual(balances["USDC"]["invested"], "40")
        investment = self.service.investments(self.alice["id"])[0]
        self.assertEqual(investment["cyclesCompleted"], 0)
        self.assertEqual(investment["terms"]["illustrativeRateBps"], 800)
        admin_investments = self.service.investments(self.admin["id"], admin=True)
        self.assertEqual(len(admin_investments), 1)
        self.assertEqual(admin_investments[0]["id"], investment["id"])
        self.assertEqual(admin_investments[0]["email"], self.alice["email"])

    def test_admin_credit_requires_reason_and_audits_request(self) -> None:
        result = self.service.admin_credit(
            self.admin["id"],
            self.alice["id"],
            "BTC",
            "0.125",
            "approved demo allocation",
            "admin-credit-once-01",
            "request-123",
        )
        self.assertEqual(result["status"], "completed_simulated")
        balances = {x["asset"]: x for x in self.service.balances(self.alice["id"])}
        self.assertEqual(balances["BTC"]["available"], "0.125")
        with closing(self.database.connect()) as connection:
            audit = connection.execute(
                "SELECT request_id, reason FROM audit_events WHERE actor_id = ?",
                (self.admin["id"],),
            ).fetchone()
        self.assertEqual(audit["request_id"], "request-123")
        self.assertEqual(audit["reason"], "approved demo allocation")

    def test_deposit_addresses_accept_real_network_addresses_and_reject_invalid_ones(self) -> None:
        bitcoin_address = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
        address = self.service.update_deposit_address(
            self.admin["id"],
            "BTC",
            "Bitcoin",
            bitcoin_address,
            True,
            "configure Bitcoin destination",
            "request-456",
        )
        self.assertEqual(address["address"], bitcoin_address)
        self.assertEqual(self.service.deposit_addresses()[0]["network"], "Bitcoin")

        tron_address = "T" + "1" * 33
        self.service.update_deposit_address(
            self.admin["id"],
            "USDT",
            "Tron-TRC20",
            tron_address,
            True,
            "configure Tron destination",
            "request-459",
        )
        self.assertTrue(
            any(
                item["asset"] == "USDT"
                and item["network"] == "Tron-TRC20"
                and item["address"] == tron_address
                for item in self.service.deposit_addresses()
            )
        )

        with self.assertRaises(DomainError) as raised:
            self.service.update_deposit_address(
                self.admin["id"],
                "BTC",
                "Bitcoin",
                "not-a-Bitcoin-address",
                True,
                "configure invalid destination",
                "request-457",
            )
        self.assertEqual(raised.exception.code, "INVALID_DEPOSIT_ADDRESS")

        placeholder = self.service.update_deposit_address(
            self.admin["id"],
            "BTC",
            "Bitcoin",
            "DEMO-BTC-RECEIVE-01",
            True,
            "configure demo destination",
            "request-458",
        )
        self.assertEqual(placeholder["address"], "DEMO-BTC-RECEIVE-01")
        self.assertEqual(self.service.deposit_addresses()[0]["asset"], "BTC")

    def test_suspension_revokes_existing_sessions(self) -> None:
        self.service.set_user_status(
            self.admin["id"],
            self.alice["id"],
            "suspended",
            "test suspension",
            "request-789",
        )
        with self.assertRaises(DomainError) as raised:
            self.service.authenticate(self.alice_token)
        self.assertEqual(raised.exception.status, 401)


class HttpIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "http.sqlite3"
        database = Database(database_path)
        database.initialize()
        BackendService(database).create_admin(ADMIN_EMAIL, ADMIN_PASSWORD)
        self.server = NexoraHTTPServer(
            ("127.0.0.1", 0),
            Config(
                database_path=database_path,
                port=0,
            ),
            database,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(self.cookie_jar))
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp_dir.cleanup()

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object], dict[str, str]]:
        body = json.dumps(payload).encode() if payload is not None else None
        request_headers = dict(headers or {})
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        request = Request(
            self.base_url + path,
            data=body,
            headers=request_headers,
            method=method,
        )
        try:
            response = self.opener.open(request)
        except HTTPError as exc:
            response = exc
        response_headers = {key.lower(): value for key, value in response.headers.items()}
        set_cookies = response.headers.get_all("Set-Cookie") or []
        if set_cookies:
            response_headers["set-cookie"] = " | ".join(set_cookies)
        return (
            response.status,
            json.loads(response.read()),
            response_headers,
        )

    def test_frontend_cors_preflight_allows_configured_origin(self) -> None:
        request = Request(
            self.base_url + "/api/v1/auth/login",
            method="OPTIONS",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )
        with self.opener.open(request) as response:
            self.assertEqual(response.status, 204)
            self.assertEqual(
                response.headers.get("Access-Control-Allow-Origin"),
                "http://localhost:5173",
            )
            self.assertEqual(response.headers.get("Access-Control-Allow-Credentials"), "true")

    def test_admin_can_publish_real_address_for_authenticated_users(self) -> None:
        status, _login, _headers = self.request(
            "POST",
            "/api/v1/auth/login",
            {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
            {"Origin": self.base_url},
        )
        self.assertEqual(status, 200)
        csrf = next(cookie.value for cookie in self.cookie_jar if cookie.name == "nexora_csrf")
        address = "0x" + "a" * 40
        status, published, _headers = self.request(
            "PUT",
            "/api/v1/admin/deposit-addresses/ETH/Ethereum-ERC20",
            {
                "address": address,
                "enabled": True,
                "reason": "publish Ethereum destination",
            },
            {"Origin": self.base_url, "X-CSRF-Token": csrf},
        )
        self.assertEqual(status, 200)
        self.assertEqual(published["data"]["address"], address)

        status, _registered, _headers = self.request(
            "POST",
            "/api/v1/auth/register",
            {"name": "Wallet User", "email": "wallet-user@example.test", "password": USER_PASSWORD},
            {"Origin": self.base_url},
        )
        self.assertEqual(status, 201)
        status, visible_addresses, _headers = self.request(
            "GET",
            "/api/v1/deposit-addresses",
        )
        self.assertEqual(status, 200)
        self.assertTrue(
            any(
                item["asset"] == "ETH"
                and item["network"] == "Ethereum-ERC20"
                and item["address"] == address
                for item in visible_addresses["data"]
            )
        )

    def test_http_registration_csrf_and_balances(self) -> None:
        status, created, headers = self.request(
            "POST",
            "/api/v1/auth/register",
            {
                "name": "HTTP User",
                "email": "http-user@example.test",
                "password": USER_PASSWORD,
            },
            {"Origin": self.base_url},
        )
        self.assertEqual(status, 201)
        self.assertIn("nexora_session=", headers["set-cookie"])

        csrf = next(
            cookie.value
            for cookie in self.cookie_jar
            if cookie.name == "nexora_csrf"
        )
        status, balances, _headers = self.request(
            "GET",
            "/api/v1/wallets/me/balances",
        )
        self.assertEqual(status, 200)
        usdc = next(item for item in balances["data"] if item["asset"] == "USDC")
        self.assertEqual(usdc["available"], "100")

        status, error, _headers = self.request(
            "POST",
            "/api/v1/investments",
            {"asset": "USDC", "amount": "10", "riskAcknowledged": True},
            {"Origin": self.base_url, "Idempotency-Key": "http-investment-01"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(error["error"]["code"], "CSRF_INVALID")

        status, result, _headers = self.request(
            "POST",
            "/api/v1/investments",
            {"asset": "USDC", "amount": "10", "riskAcknowledged": True},
            {
                "Origin": self.base_url,
                "Idempotency-Key": "http-investment-01",
                "X-CSRF-Token": csrf,
            },
        )
        self.assertEqual(status, 201, result)
        self.assertEqual(result["data"]["type"], "investment")

        recipient, _recipient_token, _recipient_csrf = self.server.service.register(
            "Recipient Example",
            "recipient@example.test",
            USER_PASSWORD,
        )
        transfer_headers = {
            "Origin": self.base_url,
            "Idempotency-Key": "http-transfer-0001",
            "X-CSRF-Token": csrf,
        }
        transfer_payload = {
            "recipientId": recipient["id"],
            "asset": "USDC",
            "amount": "5",
            "memo": "HTTP transfer",
        }
        status, transfer, _headers = self.request(
            "POST",
            "/api/v1/transfers",
            transfer_payload,
            transfer_headers,
        )
        self.assertEqual(status, 201)
        replay_status, replay, _headers = self.request(
            "POST",
            "/api/v1/transfers",
            transfer_payload,
            transfer_headers,
        )
        self.assertEqual(replay_status, 201)
        self.assertEqual(replay["data"]["id"], transfer["data"]["id"])

        status, forbidden, _headers = self.request(
            "POST",
            "/api/v1/admin/wallet-credits",
            {
                "userId": created["data"]["user"]["id"],
                "asset": "USDC",
                "amount": "1",
                "reason": "not authorized",
            },
            {
                "Origin": self.base_url,
                "Idempotency-Key": "http-admin-credit-01",
                "X-CSRF-Token": csrf,
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(forbidden["error"]["code"], "FORBIDDEN")


class AmountTests(unittest.TestCase):
    def test_large_precision_amounts_round_trip_without_float(self) -> None:
        atomic = parse_amount("123456789012345678.123456789012345678", "ETH")
        self.assertEqual(
            format_amount(atomic, "ETH"),
            "123456789012345678.123456789012345678",
        )


if __name__ == "__main__":
    unittest.main()
