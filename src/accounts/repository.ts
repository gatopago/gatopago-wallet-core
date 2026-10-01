import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import { evmChainId, parseNetworkId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { deriveAccountId } from '@gatopago/shared/v3/authorizations';
import { isAddress } from 'viem';
import type { Principal } from '../auth/principal';

export class WalletAccessError extends Error {
	constructor(readonly code: 'SESSION_REQUIRED' | 'UNAUTHENTICATED' | 'NOT_FOUND' | 'WALLET_DATA_INVALID') {
		super(code); this.name = 'WalletAccessError';
	}
}

type Row = Record<string, unknown>;
type Page = { readonly limit: number; readonly after: string };
const SESSION = `SELECT u.id AS user_id, u.disabled_at, u.auth_not_before,
  CASE WHEN ${AUTHORIZED_USER} THEN 1 ELSE 0 END AS credential_valid
  FROM users u WHERE u.environment = ? AND u.id = ?`;
const OWNERSHIP = `JOIN users u ON u.id = w.user_id`;

function session(rows: Row[], identity: Principal) {
	if (rows.length === 0) throw new WalletAccessError('SESSION_REQUIRED');
	const row = rows[0];
	if (rows.length !== 1 || !Number.isSafeInteger(row.auth_not_before) || typeof row.auth_not_before !== 'number'
		|| row.auth_not_before < 0) throw new WalletAccessError('WALLET_DATA_INVALID');
	if (row.credential_valid !== 1 || row.disabled_at !== null || identity.authTime < row.auth_not_before
		|| identity.expiresAt <= Math.floor(Date.now() / 1000)) throw new WalletAccessError('UNAUTHENTICATED');
	try { return { user_id: parseResourceId('user', row.user_id) }; }
	catch { throw new WalletAccessError('WALLET_DATA_INVALID'); }
}

function wallet(row: Row) {
	const id = parseResourceId('wallet', row.id);
	if (row.status !== 'active' && row.status !== 'archived') throw new Error('Invalid wallet');
	return { id, user_id: parseResourceId('user', row.user_id), status: row.status };
}

function account(row: Row) {
	const id = parseResourceId('walletAccount', row.id);
	const network = parseNetworkId(row.network_id);
	evmChainId(network);
	if (!['counterfactual', 'deploying', 'active', 'needs_security_sync', 'unsupported', 'retired'].includes(String(row.deployment_state))) {
		throw new Error('Invalid account instance');
	}
	return { id, wallet_id: parseResourceId('wallet', row.wallet_id),
		network_id: network, generation: 3 as const, deployment_state: String(row.deployment_state),
		// D1 is a projection. It must not expose an unverified deposit address or authorize a payment.
		spend_readiness: 'not_assessed' as const, receive_enabled: false as const };
}

function pageResult<T extends { id: string }>(rows: Row[], page: Page, parse: (row: Row) => T) {
	const data = rows.slice(0, page.limit).map(parse);
	return { data, next_cursor: rows.length > page.limit ? data.at(-1)!.id : null };
}

/** Created per request. All ownership reads start on primary and use a transactional batch.
 * Ownership is resolved from the authenticated user, never from a client-provided owner.
 * This repository does not enroll a signer, create an onchain account or reserve any funds.
 */
export class WalletRepository {
	private readonly db: D1DatabaseSession;
	constructor(database: D1Database, private readonly identity: Principal) {
		this.db = database.withSession('first-primary');
	}
	private sessionQuery() { return this.db.prepare(SESSION).bind(...authorizationValues(this.identity), this.identity.environment, this.identity.userId); }
	private authValues() { return authorizationValues(this.identity); }
	private async read(statements: D1PreparedStatement[]): Promise<Row[][]> {
		const results = await this.db.batch<Row>(statements);
		if (results.length !== statements.length || results.some((result) => !result.success || !Array.isArray(result.results))) {
			throw new WalletAccessError('WALLET_DATA_INVALID');
		}
		return results.map((result) => result.results);
	}
	async getSession() { return session((await this.read([this.sessionQuery()]))[0], this.identity); }
	async listWallets(page: Page) {
		const result = await this.read([this.sessionQuery(), this.db.prepare(`SELECT w.* FROM wallets w ${OWNERSHIP}
			WHERE ${AUTHORIZED_USER} AND w.id > ? ORDER BY w.id LIMIT ?`).bind(...this.authValues(), page.after, page.limit + 1)]);
		session(result[0], this.identity);
		try { return pageResult(result[1], page, wallet); }
		catch { throw new WalletAccessError('WALLET_DATA_INVALID'); }
	}
	async listAccounts(walletId: ResourceId<'wallet'>, page: Page) {
		const result = await this.read([this.sessionQuery(), this.walletQuery(walletId), this.db.prepare(`SELECT a.*
			FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id ${OWNERSHIP}
			WHERE ${AUTHORIZED_USER} AND w.id = ? AND a.id > ? ORDER BY a.id LIMIT ?`)
			.bind(...this.authValues(), walletId, page.after, page.limit + 1)]);
		session(result[0], this.identity);
		if (result[1].length === 0) throw new WalletAccessError('NOT_FOUND');
		try { wallet(result[1][0]); return pageResult(result[2], page, account); }
		catch { throw new WalletAccessError('WALLET_DATA_INVALID'); }
	}
	private walletQuery(id: ResourceId<'wallet'>) {
		return this.db.prepare(`SELECT w.* FROM wallets w ${OWNERSHIP} WHERE ${AUTHORIZED_USER} AND w.id = ?`).bind(...this.authValues(), id);
	}
	/** Internal resolver for inspection/execution. Never serialize commitments/pins blindly to UI. */
	async ownedAccount(walletId: ResourceId<'wallet'>, accountId: ResourceId<'walletAccount'>) {
		const result = await this.read([this.sessionQuery(), this.db.prepare(`SELECT a.*, w.account_id, w.initial_security_commitment, w.user_salt_commitment,
			w.status AS wallet_status
			FROM wallet_accounts a JOIN wallets w ON w.id = a.wallet_id ${OWNERSHIP}
			WHERE ${AUTHORIZED_USER} AND w.id = ? AND a.id = ? AND a.address = w.canonical_address`).bind(...this.authValues(), walletId, accountId)]);
		session(result[0], this.identity);
		if (result[1].length === 0) throw new WalletAccessError('NOT_FOUND');
		return parseWalletAccount(result[1][0]);
	}
}

/** Validates a persisted account identity; callers must separately establish access. */
export function parseWalletAccount(row: Row, includeArchived = false) {
	try {
		const view = account(row);
		if ((row.wallet_status !== 'active' && !(includeArchived && row.wallet_status === 'archived'))
			|| view.deployment_state === 'unsupported' || view.deployment_state === 'retired'
			|| typeof row.address !== 'string' || !isAddress(row.address, { strict: true })
			|| row.address !== row.address.toLowerCase() || /^0x0+$/.test(row.address)) throw new Error('Invalid account');
		requireHash(row.account_id); requireHash(row.initial_security_commitment); requireHash(row.user_salt_commitment);
		requireHash(row.deployment_manifest_sha256);
		if (deriveAccountId(row.initial_security_commitment, row.user_salt_commitment) !== row.account_id) throw new Error('Invalid identity');
		return Object.freeze({ ...view, address: row.address, account_id: row.account_id,
			initial_security_commitment: row.initial_security_commitment, user_salt_commitment: row.user_salt_commitment,
			deployment_manifest_sha256: row.deployment_manifest_sha256 });
	} catch { throw new WalletAccessError('WALLET_DATA_INVALID'); }
}
