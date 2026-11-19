# Nexora Investment Wallet

Responsive wallet UI connected to the Nexora backend. The market strip displays indicative spot prices from Kraken public market data.

## Run locally

```sh
npm install
npm run dev
```

Build and preview with `npm run build` and `npm run preview`.

Copy `.env.example` to `.env.local` for local development. Vite proxies `/api`
requests to the local backend, so the browser does not need cross-origin API
access. For deployment, set `VITE_API_BASE_URL` to the backend origin and
configure backend CORS for the frontend origin, then rebuild.

For local development, start the backend on `http://127.0.0.1:8000`. The Vite
proxy forwards API calls there; local CORS configuration is not needed.

Users sign up and sign in through the backend. Create the initial administrator
using `python -m nexora_backend.admin` from the backend directory. Session
cookies are HttpOnly; the frontend does not persist credentials or wallet
balances in browser storage.

## Routes

- User: `/app`, `/app/assets`, `/app/deposit`, `/app/investments`, `/app/send`, `/app/transactions`, `/app/notifications`, `/app/profile`
- Administrator: `/admin/overview`, `/admin/users`, `/admin/wallets`, `/admin/deposits`, `/admin/withdrawals`, `/admin/investments`, `/admin/send`, `/admin/transactions`, `/admin/settings`

## Connected interactions

- User and administrator dashboards, responsive navigation, saved dark/light theme, account and notification menus.
- Backend authentication, account registration, balances, transaction history, and investments.
- Internal transfers with server-side validation and idempotency keys.
- Administrator user management, simulated wallet credits, and deposit-address settings for supported networks.
- Administrator email and password updates from the admin settings page.
- External withdrawals and deposit crediting are not implemented by the backend.

## Limitations

Wallet and investment actions are simulated ledger operations only. The backend
does not process blockchain deposits or withdrawals, and it does not pay
investment returns. Administrators can publish network-formatted wallet addresses for users to
view, but the backend does not monitor on-chain deposits or credit funds.
Kraken prices are indicative and do not determine ledger balances. Verify any
address and network out of band before sending funds.
