import { getAddress, isAddress } from 'viem';
import { readActivity, reconcileTransfers } from './activity';
import { receiveAlchemyWebhook, watchMembers } from './alchemy';
import { deletePushToken, savePushToken } from './push';
import { addApproval, readApprovals } from './approvals';
import { createNonce, createSession, readSignup } from './auth';
import { Budget } from './budget';
import {
  approveBusinessLogin,
  collectBusinessLogin,
  readBusinessApproval,
  requestBusinessLogin,
} from './business';
import { bundle } from './bundler';
import { addContact, issueInvite, readContacts, readInvites, removeContact } from './contacts';
import { readCardInterest, saveCardInterest } from './card';
import { config, type Config } from './config';
import { HttpError, json, withCors } from './http';
import { sponsor } from './paymaster';
import { readProfile, readRecipient, updateProfile } from './profile';
import {
  addStellarKey,
  createStellarAccount,
  readStellar,
  readStellarRelay,
  readStellarSubmission,
  requestStellarRelay,
  submitStellar,
  syncStellar,
} from './stellar';

export { Bundler } from './bundler';
export { WalletIdentity } from './identity';
export { StellarRelayer } from './stellar';

function route(request: Request, env: Env, settings: Config): Promise<Response> {
  const { pathname } = new URL(request.url);
  const [name, id = '', extra] = pathname.startsWith('/app/v1/')
    ? pathname.slice(8).split('/')
    : [];
  if (extra !== undefined) throw new HttpError(404, 'NOT_FOUND');
  switch (`${request.method} ${name}`) {
    case 'GET auth':
      if (id === 'signup') return Promise.resolve(readSignup(settings));
      break;
    case 'POST auth':
      if (id === 'nonce') return createNonce(request, env);
      if (id === 'session') return createSession(request, env, settings);
      break;
    case 'POST business-login':
      if (!id) return requestBusinessLogin(request, env, settings);
      break;
    case 'GET business-login':
      if (id) return collectBusinessLogin(request, env, settings, id);
      break;
    case 'GET business-approvals':
      if (id) return readBusinessApproval(request, env, settings, id);
      break;
    case 'POST business-approvals':
      if (id) return approveBusinessLogin(request, env, settings, id);
      break;
    case 'GET profile':
      if (!id) return readProfile(request, env, settings);
      break;
    case 'PUT profile':
      if (!id) return updateProfile(request, env, settings);
      break;
    case 'POST webhooks':
      if (id === 'alchemy') return receiveAlchemyWebhook(request, env, settings);
      break;
    case 'POST push-tokens':
      if (!id) return savePushToken(request, env, settings);
      break;
    case 'DELETE push-tokens':
      if (id) return deletePushToken(request, env, settings, decodeURIComponent(id));
      break;
    case 'GET contacts':
      if (!id) return readContacts(request, env, settings);
      break;
    case 'POST contacts':
      if (!id) return addContact(request, env, settings);
      break;
    case 'DELETE contacts':
      if (id) return removeContact(request, env, settings, id);
      break;
    case 'GET invites':
      if (!id) return readInvites(request, env, settings);
      break;
    case 'POST invites':
      if (!id) return issueInvite(request, env, settings);
      break;
    case 'GET activity':
      if (!id) return readActivity(request, env, settings);
      break;
    case 'GET card-interest':
      if (!id) return readCardInterest(request, env, settings);
      break;
    case 'PUT card-interest':
      if (!id) return saveCardInterest(request, env, settings);
      break;
    case 'GET recipients':
      if (id) return readRecipient(request, env, id);
      break;
    case 'GET approvals':
      if (isAddress(id)) return readApprovals(request, env, getAddress(id));
      break;
    case 'POST approvals':
      if (isAddress(id)) return addApproval(request, env, settings, getAddress(id));
      break;
    case 'POST paymaster':
      if (id) return sponsor(request, env, settings, id);
      break;
    case 'POST bundler':
      if (id) return bundle(request, env, settings, id);
      break;
    case 'GET stellar':
      if (!id) return readStellar(request, env, settings);
      if (id === 'relays') return readStellarRelay(request, env, settings);
      if (id === 'submit') return readStellarSubmission(request, env, settings);
      break;
    case 'POST stellar':
      if (id === 'account') return createStellarAccount(request, env, settings);
      if (id === 'submit') return submitStellar(request, env, settings);
      if (id === 'relays') return requestStellarRelay(request, env, settings);
      if (id === 'keys') return addStellarKey(request, env, settings);
      break;
  }
  throw new HttpError(404, 'NOT_FOUND');
}

export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname === '/app/v1/health') {
      try {
        config(env);
        return json({ status: 'ok' });
      } catch (error) {
        console.error(error);
        return json({ status: 'misconfigured' }, 503);
      }
    }
    let settings: Config;
    try {
      settings = config(env);
    } catch (error) {
      console.error(error);
      return json({ error_code: 'SERVICE_UNAVAILABLE' }, 503);
    }
    // The app, and GatoPago Business for signing in (its data comes from Flow).
    const origin = request.headers.get('Origin');
    const cors = (response: Response) =>
      origin && (origin === settings.webOrigin || origin === settings.businessOrigin)
        ? withCors(response, origin)
        : response;
    if (request.method === 'OPTIONS') return cors(new Response(null, { status: 204 }));
    try {
      return cors(await route(request, env, settings));
    } catch (error) {
      if (error instanceof HttpError) return cors(json({ error_code: error.code }, error.status));
      console.error(error);
      return cors(json({ error_code: 'INTERNAL_ERROR' }, 500));
    }
  },

  /**
   * Every minute: adds new members to the webhooks and syncs Stellar. Every 10 minutes: reads what
   * webhooks missed. Hourly: forgets expired nonces, old counters and old relays.
   */
  async scheduled(controller, env) {
    // External requests are capped per run (`SUBREQUESTS_PER_RUN`); jobs resume where they stopped.
    const settings = config(env);
    const budget = new Budget(settings.subrequestsPerRun);
    if (controller.cron === '* * * * *') {
      // One failing job does not hold back the other.
      await watchMembers(env, settings, budget).catch((error: unknown) => console.error(error));
      return syncStellar(env, settings, budget);
    }
    if (controller.cron === '*/10 * * * *') return reconcileTransfers(env, settings, budget);
    const now = Math.floor(Date.now() / 1000);
    await env.WALLET_DB.batch([
      env.WALLET_DB.prepare('DELETE FROM siwe_nonces WHERE expires_at <= ?').bind(now),
      env.WALLET_DB.prepare('DELETE FROM business_logins WHERE expires_at <= ?').bind(now - 3600),
      env.WALLET_DB.prepare('DELETE FROM sponsorship_usage WHERE day < ?').bind(
        Math.floor(now / 86_400) - 1,
      ),
      env.WALLET_DB.prepare('DELETE FROM stellar_relays WHERE created_at < ?').bind(
        now - 7 * 86_400,
      ),
      env.WALLET_DB.prepare('DELETE FROM stellar_submissions WHERE created_at < ?').bind(
        now - 30 * 86_400,
      ),
    ]);
  },
} satisfies ExportedHandler<Env>;
