import { env } from 'cloudflare:workers';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseEnvironment } from '@gatopago/environment';
import manifests from '@gatopago/environment/environments.json';
import { verifyHuman } from '../src/auth/providers';
import { createInspectionClient } from '../src/chainInspection';

const config = parseEnvironment(manifests.production);
const signal = () => new AbortController().signal;
afterEach(() => vi.restoreAllMocks());

function provider(response: Response) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const request = new Request(input, init);
    expect(request.redirect).toBe('manual');
    return response;
  });
}

describe('Workers Request compatibility and provider redirects', () => {
  it('accepts a verified Turnstile response with supported request options', async () => {
    const fetch = provider(
      Response.json({ success: true, action: 'signup', hostname: config.webauthn_rp_id }),
    );
    expect(await verifyHuman(env, config, 'synthetic-token', '127.0.0.1', signal())).toBe(true);
    expect(fetch).toHaveBeenCalledOnce();
  });
  it('rejects a redirect without forwarding the Turnstile secret', async () => {
    const fetch = provider(
      new Response(null, {
        status: 302,
        headers: { Location: 'https://unexpected.example.test/' },
      }),
    );
    await expect(
      verifyHuman(env, config, 'synthetic-token', '127.0.0.1', signal()),
    ).rejects.toThrow('Siteverify unavailable');
    expect(fetch).toHaveBeenCalledOnce();
  });
  it('validates RPC request options and rejects redirected RPC responses', async () => {
    provider(Response.json({ jsonrpc: '2.0', id: 1, result: '0x66eee' }));
    expect(await createInspectionClient('https://rpc.example.test', signal()).getChainId()).toBe(
      421614,
    );
    vi.restoreAllMocks();
    const fetch = provider(
      new Response(null, {
        status: 307,
        headers: { Location: 'https://unexpected.example.test/' },
      }),
    );
    await expect(
      createInspectionClient('https://rpc.example.test', signal()).getChainId(),
    ).rejects.toThrow('Inspection RPC unavailable');
    expect(fetch).toHaveBeenCalledOnce();
  });
});
