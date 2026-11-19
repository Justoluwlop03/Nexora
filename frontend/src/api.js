const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '');
const API_LOCATION = API_BASE || 'the local API proxy (127.0.0.1:8000)';
let csrfToken = '';

async function request(path, { method = 'GET', body, idempotencyKey } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (['POST', 'PUT'].includes(method) && !path.includes('/auth/')) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;

  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      credentials: 'include',
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new Error(
      `Could not reach the wallet service at ${API_LOCATION}. For local use, start the backend from the backend folder with "python -m nexora_backend". For a hosted app, set VITE_API_BASE_URL to the backend URL and rebuild.`,
    );
  }
  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload.error?.message || `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return payload.data;
}

function idempotencyKey() {
  return globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value || '');
  return `${date.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })} · ${date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}`;
}

function mapStatus(status) {
  return status === 'completed_simulated'
    ? 'Completed · simulated'
    : status.replaceAll('_', ' ');
}

function mapTransactions(rows, userId, admin) {
  return rows.flatMap((row) => {
    const meta = row.metadata || {};
    let type = row.type;
    let owner = meta.userId || meta.toUserId || meta.fromUserId || userId;
    if (row.type === 'transfer') {
      if (!admin) {
        type = meta.fromUserId === userId ? 'Transfer out' : 'Transfer in';
      } else {
        type = 'Transfer';
      }
    } else if (row.type === 'investment') {
      type = 'Investment';
    } else if (row.type === 'withdrawal') {
      type = 'Withdrawal';
    } else if (row.type === 'withdrawal_fee_payment') {
      type = 'Withdrawal fee';
    } else if (row.type === 'admin_demo_credit') {
      type = 'Admin transfer';
    } else if (row.type === 'demo_signup_credit') {
      type = 'Deposit';
    } else {
      type = row.type.replaceAll('_', ' ');
    }

    return [{
      id: row.reference || row.id,
      type,
      asset: row.asset || meta.asset || 'USDC',
      amount: row.amount || '0',
      user: admin ? owner : userId,
      from: meta.fromUserId,
      to: meta.toUserId,
      memo: meta.memo || meta.reason || '',
      address: meta.address,
      fee: meta.fee,
      network: meta.network === 'Ethereum-ERC20'
        ? 'Ethereum · ERC-20'
        : meta.network === 'Tron-TRC20' ? 'Tron · TRC-20' : meta.network,
      date: formatDate(row.createdAt),
      status: mapStatus(row.status),
    }];
  });
}

function mapUser(user) {
  return {
    ...user,
    status: user.status === 'suspended' ? 'Suspended' : 'Active',
    joined: formatDate(user.createdAt || user.joined).split(' · ')[0],
  };
}

function mapInvestments(rows) {
  return rows.map((item) => ({
    id: item.id,
    userId: item.userId,
    email: item.email,
    asset: item.asset,
    principal: item.principal,
    started: formatDate(item.createdAt).split(' · ')[0],
    cycles: item.cyclesCompleted,
    status: item.status[0].toUpperCase() + item.status.slice(1),
  }));
}

function mapAddresses(rows) {
  return Object.fromEntries(
    rows.filter((item) => item.enabled === undefined || item.enabled).map((item) => [item.asset, item.address]),
  );
}

export async function loadSnapshot(user) {
  const admin = user.role === 'admin';
  const paths = admin
    ? [
      '/api/v1/wallets/me/balances',
      '/api/v1/admin/users',
      '/api/v1/admin/transactions',
      '/api/v1/admin/investments',
      '/api/v1/admin/deposit-addresses',
    ]
    : [
      '/api/v1/wallets/me/balances',
      '/api/v1/users',
      '/api/v1/transactions',
      '/api/v1/investments',
      '/api/v1/deposit-addresses',
    ];
  const snapshotRequests = paths.slice(0, 5).map((path) => request(path));
  snapshotRequests.push(request('/api/v1/withdrawal-fees').catch((error) => {
    if (error.status === 404) return { BTC: '0.00012', ETH: '0.0015', USDT: '2.5', USDC: '2.5' };
    throw error;
  }));
  if (!admin) snapshotRequests.push(request('/api/v1/withdrawal-eligibility').catch((error) => {
    if (error.status === 404) return {};
    throw error;
  }));
  const [balances, users, transactions, investments, addresses, withdrawalFees, withdrawalEligibility = {}] = await Promise.all(snapshotRequests);
  const balanceMap = Object.fromEntries(
    balances.map((item) => [item.asset, item.available]),
  );
  const mappedUsers = users.map(mapUser);
  if (!mappedUsers.some((item) => item.id === user.id)) mappedUsers.unshift(mapUser(user));
  if (admin) {
    for (const item of users) {
      balanceMap[item.id] = item.balances || {};
    }
  }
  return {
    user: user.id,
    users: mappedUsers,
    balances: admin
      ? Object.fromEntries(users.map((item) => [item.id, item.balances || {}]))
      : { [user.id]: balanceMap },
    transactions: mapTransactions(transactions, user.id, admin),
    investments: mapInvestments(investments),
    addresses: mapAddresses(addresses),
    depositAddresses: addresses,
    withdrawalFees,
    withdrawalEligibility,
    withdrawalFeeAddress: addresses.find((item) => item.asset === 'USDT')?.address || '',
    withdrawalFeeNetwork: addresses.find((item) => item.asset === 'USDT')?.network || '',
    rate: 8,
  };
}

export async function loadDepositAddresses() {
  return request('/api/v1/deposit-addresses');
}

export async function restoreSession() {
  const data = await request('/api/v1/me');
  csrfToken = data.csrfToken;
  return { user: data.user, state: await loadSnapshot(data.user) };
}

export async function signIn(email, password) {
  const data = await request('/api/v1/auth/login', {
    method: 'POST',
    body: { email, password },
  });
  csrfToken = data.csrfToken;
  return { user: data.user, state: await loadSnapshot(data.user) };
}

export async function signUp(name, email, password) {
  const data = await request('/api/v1/auth/register', {
    method: 'POST',
    body: { name, email, password },
  });
  csrfToken = data.csrfToken;
  return { user: data.user, state: await loadSnapshot(data.user) };
}

export async function updateAdminCredentials({ email, currentPassword, newPassword }) {
  const data = await request('/api/v1/admin/account/credentials', {
    method: 'POST',
    body: { email, currentPassword, newPassword },
  });
  csrfToken = data.csrfToken;
  return data.user;
}

export async function signOut() {
  await request('/api/v1/auth/logout', { method: 'POST', body: {} });
  csrfToken = '';
}

export async function transfer(asset, amount, recipientId, memo) {
  return request('/api/v1/transfers', {
    method: 'POST',
    body: { asset, amount, recipientId, memo },
    idempotencyKey: idempotencyKey(),
  });
}

export async function withdraw(asset, amount, address, network, memo) {
  const networkId = {
    Bitcoin: 'Bitcoin',
    'Ethereum · ERC-20': 'Ethereum-ERC20',
    'Tron · TRC-20': 'Tron-TRC20',
  }[network] || network;
  return request('/api/v1/withdrawals', {
    method: 'POST',
    body: { asset, amount, address, network: networkId, memo },
    idempotencyKey: idempotencyKey(),
  });
}

export async function payWithdrawalFee() {
  return request('/api/v1/withdrawal-fees/pay', {
    method: 'POST',
    body: {},
    idempotencyKey: idempotencyKey(),
  });
}

export async function invest(asset, amount) {
  return request('/api/v1/investments', {
    method: 'POST',
    body: { asset, amount, riskAcknowledged: true },
    idempotencyKey: idempotencyKey(),
  });
}

export async function creditUser(userId, asset, amount, reason) {
  return request('/api/v1/admin/wallet-credits', {
    method: 'POST',
    body: { userId, asset, amount, reason },
    idempotencyKey: idempotencyKey(),
  });
}

export async function setUserStatus(userId, status) {
  return request(`/api/v1/admin/users/${encodeURIComponent(userId)}/status`, {
    method: 'POST',
    body: { status: status === 'Active' ? 'active' : 'suspended', reason: 'Updated in admin console' },
  });
}

export async function deleteUser(userId) {
  return request(`/api/v1/admin/users/${encodeURIComponent(userId)}/delete`, {
    method: 'POST',
    body: { reason: 'Deleted from admin user management' },
  });
}

export async function updateDepositAddress(asset, network, address, enabled = true) {
  const networkId = {
    'Ethereum · ERC-20': 'Ethereum-ERC20',
    'Tron · TRC-20': 'Tron-TRC20',
  }[network] || network;
  return request(`/api/v1/admin/deposit-addresses/${asset}/${encodeURIComponent(networkId)}`, {
    method: 'PUT',
    body: { address, enabled, reason: 'Updated in admin console' },
  });
}

export async function updateWithdrawalFees(fees) {
  try {
    return await request('/api/v1/admin/withdrawal-fees', {
      method: 'PUT',
      body: { fees, reason: 'Updated withdrawal eligibility fees in admin console' },
    });
  } catch (error) {
    if (error.status === 404) throw new Error('The backend is outdated. Restart the backend so it can load the withdrawal fee API.');
    throw error;
  }
}
