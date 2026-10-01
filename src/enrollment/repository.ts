import { AUTHORIZED_USER, authorizationValues } from '../auth/authorization';
import { bytesToHex, hexToBytes, sha256, stringToHex } from 'viem';
import { parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { requireHash } from '@gatopago/shared/v3/deployment';
import { assertWebAuthnChallenge, assertWebAuthnScope, type WebAuthnScope } from '@gatopago/shared/v3/webauthn';
import type { Principal } from '../auth/principal';
import { WalletAccessError, WalletRepository } from '../accounts/repository';
import { base64url, EnrollmentError, type verifyEnrollment } from './verification';
import { parseCredentialInventory } from '@gatopago/shared/v3/credential-inventory';
import { parseCredentialDetail } from '@gatopago/shared/v3/credential-detail';

type Row = Record<string, unknown>;
type VerifiedEnrollment = Awaited<ReturnType<typeof verifyEnrollment>>;
const freshNow = () => Math.floor(Date.now() / 1000);

/** All instances/DB sessions are request-scoped. Pending attempts never reserve
 * a credential globally; a key becomes unique only after possession succeeds.
 */
export class EnrollmentRepository {
	private readonly db: D1DatabaseSession;
	private readonly wallets: WalletRepository;
	private readonly scope: WebAuthnScope;
	constructor(database: D1Database, private readonly identity: Principal, scope: WebAuthnScope) {
		assertWebAuthnScope(scope);
		this.scope = Object.freeze({ ...scope });
		this.db = database.withSession('first-primary');
		this.wallets = new WalletRepository(database, identity);
	}
	private auth() { return authorizationValues(this.identity); }
	private async owner() {
		if (this.identity.expiresAt <= freshNow()) throw new WalletAccessError('UNAUTHENTICATED');
		return (await this.wallets.getSession()).user_id;
	}
	private select(id: ResourceId<'operation'>) {
		return this.db.prepare(`SELECT e.* FROM webauthn_enrollments e JOIN users u ON u.id = e.user_id
			WHERE e.id = ? AND ${AUTHORIZED_USER}`).bind(id, ...this.auth());
	}
	private row(row: Row | null) {
		if (!row) throw new WalletAccessError('NOT_FOUND');
		try {
			const id = parseResourceId('operation', row.id);
			parseResourceId('user', row.user_id);
			if (row.rp_id !== this.scope.rpId || row.origin !== this.scope.origin ||
				typeof row.created_at !== 'number' || !Number.isSafeInteger(row.created_at) ||
				typeof row.expires_at !== 'number' || row.expires_at !== row.created_at + 300 ||
				(row.completed_at !== null && (typeof row.completed_at !== 'number' || row.completed_at < row.created_at || row.completed_at >= row.expires_at))) throw new Error();
			requireHash(row.challenge); requireHash(row.proof_challenge);
			assertWebAuthnChallenge(row.challenge); assertWebAuthnChallenge(row.proof_challenge);
			return { id, challenge: row.challenge, proofChallenge: row.proof_challenge, scope: this.scope,
				createdAt: row.created_at, expiresAt: row.expires_at, completedAt: row.completed_at, responseHash: row.response_hash };
		} catch { throw new WalletAccessError('WALLET_DATA_INVALID'); }
	}
	async read(id: ResourceId<'operation'>) {
		await this.owner();
		return this.row(await this.select(id).first<Row>());
	}
	async credentials() {
		const owner = await this.owner();
		// Registration is capped at 16 per owner. A seventeenth row is a data
		// inconsistency, not a silently truncated list. No cleanup/write on read.
		const rows = await this.db.prepare(`SELECT c.id,c.rp_id,c.origin,c.created_at,c.transports_json,
			c.aaguid,c.backup_eligible,c.backed_up FROM webauthn_credentials c
			JOIN users u ON u.id = c.user_id WHERE u.id = ? AND ${AUTHORIZED_USER}
			ORDER BY c.created_at, c.id LIMIT 17`).bind(owner, ...this.auth()).all<Row>();
		await this.owner(); // Revocation/expiration during the read must not become an empty list.
		try {
			if (!rows.success) throw new Error();
			const data = rows.results.map((row) => {
				if (row.rp_id !== this.scope.rpId || row.origin !== this.scope.origin ||
					typeof row.transports_json !== 'string' || row.transports_json.length > 256 ||
					(row.backup_eligible !== 0 && row.backup_eligible !== 1) || (row.backed_up !== 0 && row.backed_up !== 1)) throw new Error();
				return { credential_ref: row.id, created_at: row.created_at, transports: JSON.parse(row.transports_json) as unknown,
					aaguid: row.aaguid, backup_eligible: row.backup_eligible === 1, backed_up_at_registration: row.backed_up === 1 };
			});
			return parseCredentialInventory({ scope: this.scope, data, device_availability: 'unknown', onchain_authority: 'not_assessed' }, this.scope, freshNow());
		} catch { throw new WalletAccessError('WALLET_DATA_INVALID'); }
	}
	async credential(reference: ResourceId<'operation'>) {
		const id = parseResourceId('operation', reference), owner = await this.owner();
		const row = await this.db.prepare(`SELECT c.id,c.rp_id,c.origin,c.credential_id,c.public_key
			FROM webauthn_credentials c JOIN users u ON u.id = c.user_id
			WHERE c.id = ? AND u.id = ? AND ${AUTHORIZED_USER}`).bind(id, owner, ...this.auth()).first<Row>();
		await this.owner(); // Do not release key metadata after session revocation during the read.
		if (!row) throw new WalletAccessError('NOT_FOUND');
		try {
			return parseCredentialDetail({ scope: { rpId: row.rp_id, origin: row.origin }, credential_ref: row.id,
				credential_id: row.credential_id, public_key: row.public_key,
				device_availability: 'unknown', onchain_authority: 'not_assessed' }, this.scope, id);
		} catch { throw new WalletAccessError('WALLET_DATA_INVALID'); }
	}
	async prepare(id: ResourceId<'operation'>) {
		const owner = await this.owner(), now = freshNow();
		const random = () => bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
		await this.db.batch([
			// Bounded to this authenticated owner; 24 starts/day also bounds retained rows.
			this.db.prepare(`DELETE FROM webauthn_enrollments WHERE user_id = ? AND created_at < ?
				AND EXISTS (SELECT 1 FROM users u WHERE u.id = webauthn_enrollments.user_id AND ${AUTHORIZED_USER})`)
				.bind(owner, now - 86400, ...this.auth()),
			this.db.prepare(`INSERT INTO webauthn_enrollments (id,user_id,rp_id,origin,challenge,proof_challenge,created_at,expires_at)
				SELECT ?, u.id, ?, ?, ?, ?, ?, ? FROM users u WHERE u.id = ? AND ${AUTHORIZED_USER}
				AND (SELECT count(*) FROM webauthn_enrollments e WHERE e.user_id = u.id) < 24
				AND (SELECT count(*) FROM webauthn_enrollments e WHERE e.user_id = u.id AND e.created_at > ?) < 6
				AND (SELECT count(*) FROM webauthn_credentials c WHERE c.user_id = u.id) < 16
				ON CONFLICT(id) DO NOTHING`)
				.bind(id, this.scope.rpId, this.scope.origin, random(), random(), now, now + 300, owner, ...this.auth(), now - 600),
		]);
		await this.owner();
		const found = await this.select(id).first<Row>();
		if (!found) throw new EnrollmentError('ENROLLMENT_LIMIT');
		const attempt = this.row(found);
		if (attempt.completedAt !== null) return { enrollment_id: id, state: 'enrolled' as const, onchain_authority: false as const };
		if (now >= attempt.expiresAt) throw new EnrollmentError('ENROLLMENT_EXPIRED');
		const credentials = await this.db.prepare(`SELECT c.credential_id FROM webauthn_credentials c
			JOIN users u ON u.id = c.user_id WHERE ${AUTHORIZED_USER} AND c.rp_id = ? ORDER BY c.id LIMIT 16`)
			.bind(...this.auth(), this.scope.rpId).all<{ credential_id: string }>();
		return { enrollment_id: id, state: 'prepared' as const, expires_at: attempt.expiresAt,
			scope: this.scope, proof_challenge: attempt.proofChallenge,
			options: { challenge: base64url(hexToBytes(attempt.challenge)), rp: { id: this.scope.rpId, name: 'GatoPago' },
				user: { id: base64url(hexToBytes(sha256(stringToHex(`GatoPago V3 WebAuthn user\n${this.scope.rpId}\n${owner}`)))),
					name: `GatoPago ${owner.slice(-8)}`, displayName: 'Tu cuenta GatoPago' },
				pubKeyCredParams: [{ type: 'public-key' as const, alg: -7 }], timeout: 60000, attestation: 'none' as const,
				authenticatorSelection: { residentKey: 'required' as const, userVerification: 'required' as const },
				excludeCredentials: credentials.results.map((item) => ({ id: item.credential_id, type: 'public-key' as const })) },
			onchain_authority: false as const };
	}
	async complete(id: ResourceId<'operation'>, result: VerifiedEnrollment) {
		await this.owner();
		const now = freshNow();
		const rows = await this.db.batch<Row>([
			this.db.prepare(`INSERT OR IGNORE INTO webauthn_credentials
				(id,user_id,rp_id,origin,credential_id,public_key,transports_json,aaguid,backup_eligible,backed_up,sign_count,response_hash,created_at)
				SELECT e.id,e.user_id,e.rp_id,e.origin,?,?,?,?,?,?,?,?,? FROM webauthn_enrollments e
				JOIN users u ON u.id = e.user_id WHERE e.id = ? AND ${AUTHORIZED_USER}
				AND e.rp_id = ? AND e.origin = ? AND e.completed_at IS NULL AND e.expires_at > ?
				AND (SELECT count(*) FROM webauthn_credentials c WHERE c.user_id = u.id) < 16`)
				.bind(result.credentialId, result.publicKey, JSON.stringify(result.transports), result.aaguid,
					Number(result.backupEligible), Number(result.backedUp), result.signCount, result.responseHash, now,
					id, ...this.auth(), this.scope.rpId, this.scope.origin, now),
			this.db.prepare(`UPDATE webauthn_enrollments SET completed_at = ?, response_hash = ? WHERE id = ? AND completed_at IS NULL
				AND expires_at > ? AND EXISTS (SELECT 1 FROM users u WHERE u.id = webauthn_enrollments.user_id AND ${AUTHORIZED_USER})
				AND EXISTS (SELECT 1 FROM webauthn_credentials c WHERE c.id = webauthn_enrollments.id
					AND c.user_id = webauthn_enrollments.user_id AND c.response_hash = ?)`)
				.bind(now, result.responseHash, id, now, ...this.auth(), result.responseHash),
			this.select(id),
		]);
		if (rows.length !== 3 || rows.some((row) => !row.success) || rows.slice(0, 2).some((row) => ![0, 1].includes(row.meta.changes))) {
			throw new WalletAccessError('WALLET_DATA_INVALID');
		}
		await this.owner();
		const attempt = this.row(rows[2].results[0] ?? null);
		if (attempt.completedAt !== null && attempt.responseHash === result.responseHash) {
			return { enrollment_id: id, state: 'enrolled' as const, onchain_authority: false as const };
		}
		if (now >= attempt.expiresAt) throw new EnrollmentError('ENROLLMENT_EXPIRED');
		throw new EnrollmentError('ENROLLMENT_CONFLICT');
	}
}
