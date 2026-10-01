import { parseResourceId } from '@gatopago/shared/v3/primitives';

type CreationDeliveryState = 'pending' | 'sending' | 'uncertain' | 'accepted' | 'expired';

/** Validate the lifecycle independently of user-visible account readiness. No state here
 * asserts inclusion, finality, successful execution or permission to receive/spend. */
export function readCreationOutbox(row: Record<string, unknown>, authorizedAt: number | null, id: string, hash: string, expiresAt: number) {
	if (authorizedAt === null) {
		if (row.outbox_id !== null) throw new Error('Unexpected outbox');
		return null;
	}
	if (row.outbox_id !== id || row.outbox_hash !== hash || row.outbox_created !== authorizedAt || row.outbox_expires !== expiresAt
		|| !['pending', 'sending', 'uncertain', 'accepted', 'expired'].includes(String(row.outbox_state))) throw new Error('Invalid outbox');
	const state = row.outbox_state as CreationDeliveryState;
	const attempts = row.outbox_attempts, next = row.outbox_next;
	if (typeof attempts !== 'number' || !Number.isSafeInteger(attempts) || attempts < 0 || attempts > 32
		|| typeof next !== 'number' || !Number.isSafeInteger(next) || next < 0) throw new Error('Invalid outbox retry');
	const token = row.outbox_lease, until = row.outbox_lease_until;
	if ((token === null) !== (until === null)) throw new Error('Invalid lease');
	if (token !== null) {
		parseResourceId('operation', token);
		if (typeof until !== 'number' || !Number.isSafeInteger(until) || until <= authorizedAt || until > expiresAt
			|| !['pending', 'sending'].includes(state)) throw new Error('Invalid lease');
	}
	const started = row.outbox_started, accepted = row.outbox_accepted;
	if (['sending', 'uncertain', 'accepted'].includes(state)) {
		if (typeof started !== 'number' || !Number.isSafeInteger(started) || started < authorizedAt || started >= expiresAt || attempts < 1) throw new Error('Invalid send state');
	} else if (started !== null) throw new Error('Unexpected send state');
	if (state === 'sending' && token === null) throw new Error('Missing send lease');
	if (state === 'accepted') {
		if (typeof accepted !== 'number' || !Number.isSafeInteger(accepted) || typeof started !== 'number' || accepted < started) throw new Error('Invalid acceptance');
	} else if (accepted !== null) throw new Error('Unexpected acceptance');
	return Object.freeze({ state, attempts, next, token, until, started, accepted });
}

export const creationOutboxColumns = `b.initialization_id AS outbox_id, b.user_op_hash AS outbox_hash,
	b.state AS outbox_state, b.created_at AS outbox_created, b.expires_at AS outbox_expires,
	b.lease_token AS outbox_lease, b.lease_expires_at AS outbox_lease_until, b.attempt_count AS outbox_attempts,
	b.next_attempt_at AS outbox_next, b.send_started_at AS outbox_started, b.accepted_at AS outbox_accepted`;
