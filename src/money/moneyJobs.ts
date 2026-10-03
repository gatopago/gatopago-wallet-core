import type { Environment } from '@gatopago/environment';
import { loadPinnedDeploymentManifest } from '@gatopago/shared/v3/deployment';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { loadAaveMarket, type AaveMarketPin } from '@gatopago/shared/v3/aave-market';
import { readMoneyHistory } from './moneyHistoricalRecord';

export interface MoneyWake {
  readonly schema_version: 1;
  readonly kind: 'money_observation';
  readonly operation_id: ResourceId<'operation'>;
  readonly token: ResourceId<'operation'>;
}
export function parseMoneyWake(value: unknown): MoneyWake {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 4
    || Reflect.get(value, 'schema_version') !== 1 || Reflect.get(value, 'kind') !== 'money_observation') {
    throw new Error('INVALID_MONEY_WAKE');
  }
  return Object.freeze({ schema_version: 1, kind: 'money_observation',
    operation_id: parseResourceId('operation', Reflect.get(value, 'operation_id')),
    token: parseResourceId('operation', Reflect.get(value, 'token')) });
}
export interface MoneyJobScope {
  readonly environment: Environment['environment'];
  readonly profiles: readonly { readonly document: string; readonly digest: `0x${string}`; readonly market: AaveMarketPin }[];
}
const changed = (result: D1Result) => {
  if (!result.success || ![0, 1].includes(result.meta.changes)) throw new Error('MONEY_JOB_STORAGE');
  return result.meta.changes === 1;
};

/** Scheduler scope is server-owned, not a Firebase session fabricated for a job.
 * Disabled/expired logins do not erase the obligation to observe a prior send.
 * No method here broadcasts, changes a nonce hold, or asserts receipt finality.
 */
export class MoneyJobRepository {
  private readonly db: D1DatabaseSession;
  private readonly environment: Environment['environment'];
  private readonly pins: readonly string[];
  constructor(private readonly database: D1Database, configuration: MoneyJobScope) {
    if (configuration.environment !== 'production' || configuration.profiles.length > 32) {
      throw new Error('MONEY_JOB_CONFIGURATION');
    }
    const pins = configuration.profiles.map(pin => { loadPinnedDeploymentManifest(pin.document, pin.digest); loadAaveMarket(pin.market); return pin.digest + ':' + pin.market.digest; });
    if (new Set(pins).size !== pins.length) throw new Error('MONEY_JOB_CONFIGURATION');
    this.environment = configuration.environment; this.pins = Object.freeze(pins);
    this.db = database.withSession('first-primary');
  }
  private scope() {
    return `EXISTS (SELECT 1 FROM money_operations r
      JOIN wallets w ON w.id = r.wallet_id JOIN users u ON u.id = w.user_id
      WHERE r.id = money_jobs.operation_id AND r.state IN ('dispatch_pending','submitted','confirming','review_required')
      AND u.environment = ? AND (r.deployment_manifest_sha256 || ':' || r.market_sha256) IN (${this.pins.map(() => '?').join(',')}))`;
  }
  /** Historical signed record only, with independent lease revalidation after
   * cryptographic work. It cannot be used as current signing/spending authority.
   */
  async observationSource(input: MoneyWake) {
    const message = parseMoneyWake(input);
    if (!this.pins.length) throw new Error('MONEY_JOB_SCOPE');
    const read = () => this.database.withSession('first-primary').prepare(`SELECT r.*,
      c.account_id AS identity_account_id,c.initial_security_commitment,c.user_salt_commitment
      FROM money_jobs JOIN money_operations r ON r.id = money_jobs.operation_id
      JOIN wallet_accounts a ON a.id = r.wallet_account_id AND a.wallet_id = r.wallet_id AND a.network_id = r.network_id
      JOIN wallets c ON c.id = r.wallet_id AND c.id = a.wallet_id AND c.canonical_address = r.account_address
        AND a.address = r.account_address AND a.deployment_manifest_sha256 = r.deployment_manifest_sha256
      WHERE money_jobs.operation_id = ? AND money_jobs.lease_token = ? AND money_jobs.state = 'running'
      AND money_jobs.lease_expires_at > unixepoch() AND ${this.scope()}`)
      .bind(message.operation_id, message.token, this.environment, ...this.pins).first();
    const restored = await readMoneyHistory(read), row = restored.row;
    if (typeof row.dispatch_started_at !== 'number' || !Number.isSafeInteger(row.dispatch_started_at) || row.dispatch_started_at <= 0) throw new Error('MONEY_JOB_RECORD');
    return Object.freeze({ record: restored.record, startedAt: row.dispatch_started_at, walletAccountId: restored.walletAccountId,
      context: restored.context, initialSecurityCommitment: restored.initialSecurityCommitment, userSaltCommitment: restored.userSaltCommitment });
  }
  async due(limit = 20) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50) throw new Error('INVALID_MONEY_SWEEP');
    if (!this.pins.length) return [];
    const result = await this.db.prepare(`SELECT operation_id FROM money_jobs WHERE state IN ('ready','queued','running')
      AND next_attempt_at <= unixepoch() AND (lease_expires_at IS NULL OR lease_expires_at <= unixepoch()) AND ${this.scope()}
      ORDER BY next_attempt_at,operation_id LIMIT ?`).bind(this.environment, ...this.pins, limit).all<{ operation_id: string }>();
    if (!result.success) throw new Error('MONEY_JOB_STORAGE');
    return result.results.map(row => parseResourceId('operation', row.operation_id));
  }
  async reserve(id: ResourceId<'operation'>): Promise<MoneyWake | null> {
    parseResourceId('operation', id); if (!this.pins.length) return null;
    const token = createResourceId('operation');
    const result = await this.db.prepare(`UPDATE money_jobs SET state = 'queued',lease_token = ?,lease_expires_at = unixepoch() + 120
      WHERE operation_id = ? AND state IN ('ready','queued','running') AND next_attempt_at <= unixepoch()
      AND (lease_expires_at IS NULL OR lease_expires_at <= unixepoch()) AND ${this.scope()}`)
      .bind(token, id, this.environment, ...this.pins).run();
    return changed(result) ? Object.freeze({ schema_version: 1, kind: 'money_observation', operation_id: id, token }) : null;
  }
  async claim(input: MoneyWake) {
    const message = parseMoneyWake(input); if (!this.pins.length) return false;
    return changed(await this.db.prepare(`UPDATE money_jobs SET state = 'running',lease_expires_at = unixepoch() + 180
      WHERE operation_id = ? AND lease_token = ? AND state = 'queued' AND lease_expires_at > unixepoch() AND ${this.scope()}`)
      .bind(message.operation_id, message.token, this.environment, ...this.pins).run());
  }
  async defer(input: MoneyWake, seconds: number) {
    const message = parseMoneyWake(input);
    if (!Number.isSafeInteger(seconds) || seconds < 5 || seconds > 3600) throw new Error('INVALID_MONEY_RETRY');
    if (!this.pins.length) return false;
    return changed(await this.db.prepare(`UPDATE money_jobs SET state = 'ready',next_attempt_at = unixepoch() + ?,
      failures = 0,lease_token = NULL,lease_expires_at = NULL WHERE operation_id = ? AND lease_token = ?
      AND state = 'running' AND lease_expires_at > unixepoch() AND ${this.scope()}`)
      .bind(seconds, message.operation_id, message.token, this.environment, ...this.pins).run());
  }
  async review(input: MoneyWake, reason: 'observation_timeout' | 'conflicting_evidence') {
    const message = parseMoneyWake(input);
    if (!['observation_timeout','conflicting_evidence'].includes(reason)) throw new Error('INVALID_MONEY_REVIEW');
    if (!this.pins.length) return false;
    const result = await this.db.prepare(`UPDATE money_jobs SET state = 'review',reason = ?,lease_token = NULL,lease_expires_at = NULL
      WHERE operation_id = ? AND lease_token = ? AND state = 'running' AND lease_expires_at > unixepoch() AND ${this.scope()}
      RETURNING operation_id`)
      .bind(reason, message.operation_id, message.token, this.environment, ...this.pins).first<{ operation_id: string }>();
    return result?.operation_id === message.operation_id;
  }
  async fail(input: MoneyWake, state: 'queued' | 'running') {
    const message = parseMoneyWake(input);
    if (!['queued','running'].includes(state)) throw new Error('INVALID_MONEY_JOB_STATE');
    if (!this.pins.length) return false;
    const result = await this.db.prepare(`UPDATE money_jobs SET state = CASE WHEN failures >= 7 THEN 'review' ELSE 'ready' END,
      reason = CASE WHEN failures >= 7 THEN 'processing_error' ELSE NULL END,
      next_attempt_at = unixepoch() + min(3600,30 * (1 << failures)),failures = min(8,failures + 1),lease_token = NULL,lease_expires_at = NULL
      WHERE operation_id = ? AND lease_token = ? AND state = ? AND lease_expires_at > unixepoch() AND ${this.scope()}
      RETURNING operation_id`)
      .bind(message.operation_id, message.token, state, this.environment, ...this.pins).first<{ operation_id: string }>();
    return result?.operation_id === message.operation_id;
  }
}
