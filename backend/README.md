# Nexora backend

Python API backend for the Nexora demo wallet. The frontend connects to this
service for authentication, wallet balances, internal transfers, investment
records, and administrator operations.

The API persists demo accounts and ledger activity in SQLite by default, or in
PostgreSQL when `NEXORA_DATABASE_URL` is set. It supports
registration/sign-in, balances, internal demo transfers, illustrative
investment positions, admin-only demo credits, admin user controls, and
administrator-managed deposit-address settings.

## Requirements

- Python 3.11 or newer
- Dependencies listed in `pyproject.toml`

## Run locally

From the `backend` directory:

```powershell
python -m nexora_backend.admin
python -m nexora_backend
```

For PostgreSQL, install the backend package and set `NEXORA_DATABASE_URL` to
the connection URL provided by your database host before running either
command. Keep the URL in a deployment secret or environment variable; do not
add it to source control. The schema and demo asset seed data are created
automatically on startup.

Install the declared database driver from the `backend` directory with
`python -m pip install .`.

The first command interactively creates an administrator. Use a unique email
and a password with at least 16 characters. The password is not written to a
file. The API listens on `http://127.0.0.1:8000` by default and creates
`backend/data/nexora.sqlite3` on first run.

The backend loads `backend/.env` automatically at startup. Copy
`backend/.env.example` to `backend/.env` and edit it as needed. Values already
set in the shell take precedence. The local `.env` is ignored by Git; do not
commit database credentials or other secrets. No database secret is needed for
the default local SQLite setup.

The frontend already has `frontend/.env.example`. Copy it to
`frontend/.env.local` only when you need to set `VITE_API_BASE_URL`; leave it
empty for local development, where Vite proxies `/api` to the backend.

Set configuration with environment variables or `backend/.env`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEXORA_HOST` | `127.0.0.1` | Bind address; keep loopback for local development |
| `NEXORA_PORT` | `8000` | HTTP port |
| `NEXORA_DATABASE` | `backend/data/nexora.sqlite3` | SQLite database path; also accepts a PostgreSQL URL |
| `NEXORA_DATABASE_URL` | unset | PostgreSQL connection URL; takes precedence over `NEXORA_DATABASE` |
| `NEXORA_SESSION_DAYS` | `7` | Session lifetime, from 1 to 90 days |
| `NEXORA_SECURE_COOKIES` | `false` | Set `true` behind HTTPS in deployment |
| `NEXORA_FRONTEND_ORIGIN` | `http://localhost:5173` | Exact frontend origin allowed for credentialed browser API calls |
| `NEXORA_COOKIE_SAMESITE` | `Strict` | Cookie policy; use `None` with `NEXORA_SECURE_COOKIES=true` when frontend/backend are cross-site |

When deploying frontend and backend on different origins, set
`NEXORA_FRONTEND_ORIGIN` to the frontend origin (scheme and host, no path),
`NEXORA_SECURE_COOKIES=true`, and `NEXORA_COOKIE_SAMESITE=None`. Set the
frontend's `VITE_API_BASE_URL` to the backend origin and rebuild the frontend.
For local development, the frontend origin is commonly
`http://localhost:5173`, which is the default.
For a hosted service, bind to `0.0.0.0` and use the port assigned by the hosting
platform.

On Render, the backend reads Render's `PORT` automatically and binds to
`0.0.0.0` when `NEXORA_HOST` is not explicitly set. Set
`NEXORA_FRONTEND_ORIGIN` to the deployed frontend origin and configure secure
cookies in the Render dashboard; the ignored local `.env` file is not deployed.

The development server is intentionally bound to loopback. Do not expose it
directly to the internet. Production deployment needs a TLS-terminating reverse
proxy, managed secrets, stronger persistent rate limiting, monitoring and
operational review.

## API outline

All endpoints use JSON under `/api/v1`:

- `GET /health`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/me`
- `GET /api/v1/users` (authenticated active-user directory for internal transfers)
- `GET /api/v1/assets`
- `GET /api/v1/wallets/me/balances`
- `GET /api/v1/deposit-addresses`
- `GET /api/v1/withdrawal-fees`
- `GET /api/v1/withdrawal-eligibility`
- `GET /api/v1/transactions`
- `POST /api/v1/transfers`
- `POST /api/v1/withdrawal-fees/pay`
- `POST /api/v1/withdrawals`
- `GET, POST /api/v1/investments`
- `GET /api/v1/admin/users`
- `GET /api/v1/admin/transactions`
- `GET /api/v1/admin/investments`
- `GET /api/v1/admin/deposit-addresses`
- `POST /api/v1/admin/wallet-credits`
- `POST /api/v1/admin/account/credentials`
- `PUT /api/v1/admin/deposit-addresses/{asset}/{network}`
- `POST /api/v1/admin/users/{id}/status`

Authenticated writes require the session cookie and the matching
`X-CSRF-Token` header. Registration and login return `nexora_session` (HttpOnly)
and `nexora_csrf` cookies. Idempotent ledger writes require an
`Idempotency-Key` header. API responses include a `requestId`; errors have
`error.code` and `error.message`.

## Safety and implementation boundary

- All balances and credits are explicitly simulated. New accounts start with
  zero balances; administrators may add simulated credits from the admin console.
- Internal transfers use an atomic, balanced ledger journal. Amounts are
  decimal strings converted to integer atomic units; journal rows are immutable.
- Users pay one admin-configured USDT withdrawal fee in a separate ledger
  transaction recorded to the published USDT address before submitting one
  withdrawal. The backend enforces the payment and consumes eligibility when
  the withdrawal is recorded; no on-chain transaction is sent.
- Administrators can publish BTC, Ethereum/ERC-20, and Tron/TRC-20 addresses
  for supported assets. Authenticated users can view enabled addresses by
  asset and network. Publishing an address does not connect it to custody,
  monitor the blockchain, or credit deposits.
- External withdrawals, blockchain custody/signing, on-chain deposit detection,
  real investment yield and payouts are intentionally not implemented.
- The illustrative investment terms (8% per seven-day cycle) are snapshotted for
  display only. No cycle worker credits returns.
- Admin actions require server-side role checks and an audit reason. Bootstrap
  passwords are never hard-coded.
- Administrators can update their email and password from admin settings after
  confirming the current password; the update rotates the active session and
  revokes other administrator sessions.
- The in-memory login limiter is a development safeguard, not a substitute for
  an edge/WAF or persistent production rate limiting.

## Tests

From `backend`:

```powershell
python -m unittest discover -s tests -v
```

Tests use temporary SQLite databases and do not touch the frontend or the
development database.
