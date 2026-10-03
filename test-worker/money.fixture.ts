import type { MoneyKind } from '@gatopago/shared/v3/money-wire';
import { createMoneyFixture } from '../test/money.fixture';
import { seedUser } from './user.fixture';
import { testPrincipal } from './principal.fixture';

/** Ephemeral passkey and synthetic account/funding data. No real user, signer,
 * financial execution, deployed policy or admission is implied by this fixture. */
export async function seedMoneyFixture(database: D1Database, kind: MoneyKind = 'aave_supply') {
  const fixture = createMoneyFixture(kind), { initial, now, walletId, accountId, deployment } = fixture;
  const identity = testPrincipal('money-repository-test'); await seedUser(database, identity);
  await database.batch([
    database.prepare(`INSERT INTO wallets(id,user_id,status,account_id,initial_security_commitment,user_salt_commitment,canonical_address,created_at)
      VALUES (?,?,'active',?,?,?,?,?)`).bind(walletId, identity.userId, initial.message.accountId,
        initial.message.initialSecurityCommitment, initial.message.userSaltCommitment, initial.account.toLowerCase(), now),
    database.prepare(`INSERT INTO wallet_accounts(id,wallet_id,network_id,address,deployment_manifest_sha256,deployment_state,created_at)
      VALUES (?,?,'eip155:421614',?,?,'active',?)`).bind(accountId, walletId, initial.account.toLowerCase(), deployment, now),
  ]);
  return { ...fixture, identity };
}
