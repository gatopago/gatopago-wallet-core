import { getAddress, isAddress } from 'viem';
import { readActivity, reconcileTransfers } from './activity';
import { receiveAlchemyWebhook, watchMembers } from './alchemy';
import { deletePushToken, savePushToken } from './push';
import { addApproval, readApprovals } from './approvals';
import { createNonce, createSession } from './auth';
import { bundle } from './bundler';
import { addContact, issueInvite, readContacts, readInvites, removeContact } from './contacts';
import { readCardInterest, saveCardInterest } from './card';
import { config, type Config } from './config';
import { HttpError, json, withCors } from './http';
import { sponsor } from './paymaster';
import { readProfile, readRecipient, updateProfile } from './profile';

export { Bundler } from './bundler';
export { WalletIdentity } from './identity';

function route(request: Request, env: Env, settings: Config): Promise<Response> {
  const { pathname } = new URL(request.url);
  const [name, id = '', extra] = pathname.startsWith('/app/v1/')
    ? pathname.slice(8).split('/')
    : [];
  if (extra !== undefined) throw new HttpError(404, 'NOT_FOUND');
  switch (`${request.method} ${name}`) {
    case 'POST auth':
      if (id === 'nonce') return createNonce(request, env);
      if (id === 'session') return createSession(request, env, settings);
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
    const cors = (response: Response) =>
      request.headers.get('Origin') === settings.webOrigin
        ? withCors(response, settings.webOrigin)
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
   * Every minute: adds new members to the webhooks. Every 10 minutes: reads what webhooks missed.
   * Hourly: forgets expired nonces and old counters.
   */
  async scheduled(controller, env) {
    if (controller.cron === '* * * * *') return watchMembers(env, config(env));
    if (controller.cron === '*/10 * * * *') return reconcileTransfers(env, config(env));
    const now = Math.floor(Date.now() / 1000);
    await env.WALLET_DB.batch([
      env.WALLET_DB.prepare('DELETE FROM siwe_nonces WHERE expires_at <= ?').bind(now),
      env.WALLET_DB.prepare('DELETE FROM sponsorship_usage WHERE day < ?').bind(
        Math.floor(now / 86_400) - 1,
      ),
    ]);
  },
} satisfies ExportedHandler<Env>;
