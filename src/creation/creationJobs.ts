import type { Environment } from '@gatopago/environment';
import { createResourceId, parseResourceId, type ResourceId } from '@gatopago/shared/v3/primitives';
import { CreationDeliveryRepository, type CreationDeliveryConfiguration } from './creationDelivery';

type Row = Record<string, unknown>;
export interface CreationWake {
  readonly schema_version: 1;
  readonly kind: 'account_creation';
  readonly initialization_id: ResourceId<'operation'>;
  readonly token: ResourceId<'operation'>;
}
export type CreationJobOutcome =
  | { readonly state: 'ready'; readonly next: number }
  | { readonly state: 'complete'; readonly reason: 'projected' | 'expired' }
  | {
      readonly state: 'review';
      readonly reason: 'revoked' | 'execution_reverted' | 'observation_timeout';
    };
const nowSeconds = () => Math.floor(Date.now() / 1000);
function changed(result: D1Result) {
  if (!result.success || ![0, 1].includes(result.meta.changes))
    throw new Error('CREATION_JOB_STORAGE');
  return result.meta.changes === 1;
}
export function parseCreationWake(value: unknown): CreationWake {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== 4 ||
    Reflect.get(value, 'schema_version') !== 1 ||
    Reflect.get(value, 'kind') !== 'account_creation'
  )
    throw new Error('INVALID_CREATION_WAKE');
  return Object.freeze({
    schema_version: 1,
    kind: 'account_creation',
    initialization_id: parseResourceId('operation', Reflect.get(value, 'initialization_id')),
    token: parseResourceId('operation', Reflect.get(value, 'token')),
  });
}

/** Private durable work, scoped to admitted profiles AND the application environment.
 * Queues are hints. D1 leases fence old/duplicate messages, while the delivery
 * repository separately fences the external send. No JWT or proof leaves D1.
 */
export class CreationJobRepository {
  private readonly db: D1DatabaseSession;
  private readonly pins: readonly string[];
  private readonly environment: Environment['environment'];
  constructor(database: D1Database, configuration: CreationDeliveryConfiguration) {
    new CreationDeliveryRepository(database, configuration); // Validate/detach trusted scope and pins.
    this.environment = configuration.environment;
    this.pins = Object.freeze(configuration.profiles.map((p) => p.digest));
    this.db = database.withSession('first-primary');
  }
  private scope() {
    return `EXISTS (SELECT 1 FROM account_initializations i JOIN users u ON u.id = i.user_id
			WHERE i.id = account_creation_jobs.initialization_id AND u.environment = ?
			AND i.profile_sha256 IN (${this.pins.map(() => '?').join(',')}))`;
  }
  async due(limit = 20) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50)
      throw new Error('INVALID_CREATION_SWEEP');
    if (!this.pins.length) return [];
    const now = nowSeconds();
    const rows = await this.db
      .prepare(
        `SELECT initialization_id FROM account_creation_jobs
			WHERE state IN ('ready','queued','running') AND next_attempt_at <= ?
			AND (lease_expires_at IS NULL OR lease_expires_at <= ?) AND ${this.scope()}
			ORDER BY next_attempt_at, initialization_id LIMIT ?`,
      )
      .bind(now, now, this.environment, ...this.pins, limit)
      .all<Row>();
    if (!rows.success) throw new Error('CREATION_JOB_STORAGE');
    return rows.results.map((r) => parseResourceId('operation', r.initialization_id));
  }
  async reserve(id: ResourceId<'operation'>): Promise<CreationWake | null> {
    parseResourceId('operation', id);
    if (!this.pins.length) return null;
    const token = createResourceId('operation'),
      now = nowSeconds();
    const won = changed(
      await this.db
        .prepare(
          `UPDATE account_creation_jobs SET state = 'queued', lease_token = ?, lease_expires_at = ?
			WHERE initialization_id = ? AND state IN ('ready','queued','running') AND next_attempt_at <= ?
			AND (lease_expires_at IS NULL OR lease_expires_at <= ?) AND ${this.scope()}`,
        )
        .bind(token, now + 120, id, now, now, this.environment, ...this.pins)
        .run(),
    );
    return won
      ? Object.freeze({ schema_version: 1, kind: 'account_creation', initialization_id: id, token })
      : null;
  }
  async claim(input: CreationWake) {
    const message = parseCreationWake(input);
    if (!this.pins.length) return false;
    const now = nowSeconds();
    return changed(
      await this.db
        .prepare(
          `UPDATE account_creation_jobs SET state = 'running', lease_expires_at = ?
			WHERE initialization_id = ? AND state = 'queued' AND lease_token = ? AND lease_expires_at > ? AND ${this.scope()}`,
        )
        .bind(
          now + 180,
          message.initialization_id,
          message.token,
          now,
          this.environment,
          ...this.pins,
        )
        .run(),
    );
  }
  async finish(input: CreationWake, outcome: CreationJobOutcome) {
    const message = parseCreationWake(input),
      now = nowSeconds();
    const next = outcome.state === 'ready' ? outcome.next : now;
    if (!Number.isSafeInteger(next) || next < now || next > now + 3600)
      throw new Error('INVALID_CREATION_RETRY');
    return changed(
      await this.db
        .prepare(
          `UPDATE account_creation_jobs SET state = ?, next_attempt_at = ?, failures = 0,
			lease_token = NULL, lease_expires_at = NULL, reason = ?
			WHERE initialization_id = ? AND lease_token = ? AND state = 'running' AND lease_expires_at > ?`,
        )
        .bind(
          outcome.state,
          next,
          outcome.state === 'ready' ? null : outcome.reason,
          message.initialization_id,
          message.token,
          now,
        )
        .run(),
    );
  }
  /** A failed enqueue may already have succeeded remotely. Invalidate its token;
   * any late message is harmless. Never release a consumer's already-running lease. */
  async fail(input: CreationWake, state: 'queued' | 'running') {
    const message = parseCreationWake(input),
      now = nowSeconds();
    return changed(
      await this.db
        .prepare(
          `UPDATE account_creation_jobs SET
			state = CASE WHEN failures >= 7 THEN 'review' ELSE 'ready' END,
			reason = CASE WHEN failures >= 7 THEN 'processing_error' ELSE NULL END,
			next_attempt_at = ? + min(3600, 30 * (1 << failures)), failures = min(8, failures + 1),
			lease_token = NULL, lease_expires_at = NULL
			WHERE initialization_id = ? AND lease_token = ? AND state = ? AND lease_expires_at > ?`,
        )
        .bind(now, message.initialization_id, message.token, state, now)
        .run(),
    );
  }
}
