import { testPrincipal } from './principal.fixture';
import { seedUser } from './user.fixture';
import { env } from 'cloudflare:workers';
import { createResourceId } from '@gatopago/shared/v3/primitives';
import type { Principal } from '../src/auth/principal';
import { CreationOperationRepository } from '../src/creation/creationOperation';
import { InitializationRepository, type CreationProfilePin } from '../src/creation/initialization';
import { initializationFixture } from '@gatopago/test-fixtures/v3-initialization';
import { fixtureHash } from '@gatopago/test-fixtures/v3-inspection';

export const deliveryNow = () => Math.floor(Date.now() / 1000);
export const deliveryIdentity = (subject = 'delivery-a'): Principal =>
  testPrincipal(subject, { expiresAt: deliveryNow() + 120 });
export const creationGas = () => ({
  verificationGasLimit: 2_000_000n,
  callGasLimit: 100_000n,
  preVerificationGas: 150_000n,
  maxFeePerGas: 1_000_000_000n,
  maxPriorityFeePerGas: 0n,
  maximumGasCharge: 2_250_000_000_000_000n,
});

export async function seedCreationDelivery(
  principal = deliveryIdentity(),
  pin?: CreationProfilePin,
) {
  const f = initializationFixture(),
    profile = pin ?? f.pin,
    scope = f.input.scope;
  const session = await seedUser(env.WALLET_DB, principal);
  const credentialRef = createResourceId('operation'),
    id = createResourceId('operation');
  await env.WALLET_DB.prepare(
    `INSERT INTO webauthn_credentials
		(id,user_id,rp_id,origin,credential_id,public_key,transports_json,aaguid,backup_eligible,backed_up,sign_count,response_hash,created_at)
		VALUES (?,?,?,?,?,?,'["internal"]','00000000-0000-0000-0000-000000000000',0,0,1,?,?)`,
  )
    .bind(
      credentialRef,
      session.user_id,
      scope.rpId,
      scope.origin,
      Buffer.from(credentialRef).toString('base64url'),
      f.input.publicKey,
      fixtureHash('1'),
      deliveryNow(),
    )
    .run();
  const initializations = new InitializationRepository(env.WALLET_DB, principal, scope, [profile]);
  const initial = await initializations.prepare({
    id,
    credentialRef,
    profileDigest: profile.digest,
    userSaltCommitment: f.input.userSaltCommitment,
  });
  await initializations.authorize(id, f.assertion(initial.approval_digest));
  const operations = new CreationOperationRepository(env.WALLET_DB, principal, scope, [profile]);
  const prepared = await operations.prepare(id, creationGas());
  await operations.authorize(id, f.assertion(prepared.operation_digest));
  const restored = await operations.read(id);
  if (!restored.signed) throw new Error('Synthetic operation must be signed');
  return {
    id,
    credentialRef,
    session,
    principal,
    f,
    initial,
    operations,
    signed: restored.signed,
    configuration: { environment: principal.environment, scope, profiles: [profile] },
  };
}
export const deliveryOutbox = (id: string) =>
  env.WALLET_DB.prepare('SELECT * FROM account_creation_outbox WHERE initialization_id = ?')
    .bind(id)
    .first();
export const cleanCreationDelivery = () =>
  env.WALLET_DB.exec(`DROP TRIGGER IF EXISTS delivery_fail_transition;
	DROP TRIGGER IF EXISTS observation_fail_head;
	DELETE FROM user_operation_submissions; DELETE FROM account_creation_projections;
	DELETE FROM account_creation_observations; DELETE FROM account_creation_observation_jobs;
	DELETE FROM account_creation_outbox; DELETE FROM account_creation_operations; DELETE FROM account_initializations;
	DELETE FROM webauthn_credentials; DELETE FROM webauthn_enrollments; DELETE FROM wallet_accounts;
	DELETE FROM wallets; DELETE FROM users;`);
