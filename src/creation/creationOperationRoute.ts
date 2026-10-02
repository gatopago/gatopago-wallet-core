import type { GasSponsor } from '../sponsorship/service';
import type { Principal } from '../auth/principal';
import { prepareCreationOperation } from '@gatopago/shared/v3/creation-operation';
import { abortable } from '../deadline';
import type { Environment } from '@gatopago/environment';
import { CLIENT_RELEASE_HEADERS } from '@gatopago/shared/v3/client-release';
import { type CreationGasTerms } from '@gatopago/shared/v3/creation-operation';
import { parseCreationCapRequest } from '@gatopago/shared/v3/creation-operation-wire';
import { loadPinnedCreationProfile } from '@gatopago/shared/v3/initialization';
import { parseInitializationProof } from '@gatopago/shared/v3/initialization-wire';
import { parseResourceId } from '@gatopago/shared/v3/primitives';
import { readJsonBounded, ResponseBodyTooLargeError } from '@gatopago/shared/http';
import { validateIdentityConfig, type AuthBindings } from '../auth/config';
import { IdentityError } from '../auth/identity';
import { verifyAppSession } from '../auth/session';
import type { ReceivingProfiles } from '../accounts/profile';
import { requireCurrentProtocol } from '../clientProtocol';
import { allowMethods, isJsonRequest, v3Json } from '../http';
import { InitializationError, InitializationRepository, type CreationProfilePin } from './initialization';
import { CreationOperationError, CreationOperationRepository } from './creationOperation';
import { WalletAccessError, WalletRepository } from '../accounts/repository';

const PATH = /^\/app\/v1\/account-initializations\/([^/]+)\/creation-operation(\/authorize)?$(?![\s\S])/;
const headers = ['Authorization', 'Content-Type', ...Object.values(CLIENT_RELEASE_HEADERS)];
export const isCreationOperationPath = (path: string) => PATH.test(path);
type Initial = Awaited<ReturnType<InitializationRepository['readAuthorized']>>;

/** Server-owned composition only. Gas terms bind the pinned creation operation;
 * delivery estimates the signed operation. Admission comes from the runtime catalog.
 * This API records an outbox; it neither sends inline nor asserts deployment.
 */
export function createCreationOperationRoute(dependencies: {
  readonly accessProfiles?: ReceivingProfiles;
	readonly profiles: readonly (CreationProfilePin & { readonly environment: Environment['environment'] })[];
	readonly requireFreshDeployment: (pin: CreationProfilePin, signal: AbortSignal) => Promise<void>;
	readonly sponsor?: (pin: CreationProfilePin, database: D1Database, identity: Principal, signal: AbortSignal) => GasSponsor | undefined;
	/** Server-admitted ceiling for an empty preparation request. Not a spending grant. */
	readonly automaticGasCap?: (pin: CreationProfilePin, initial: Initial, signal: AbortSignal) => Promise<bigint>;
	readonly quoteGas: (pin: CreationProfilePin, initial: Initial, cap: bigint, signal: AbortSignal) => Promise<CreationGasTerms>;
}) {
	const profiles = dependencies.profiles.map((p) => Object.freeze({ pin: Object.freeze({ document: p.document, digest: p.digest }),
		environment: p.environment, deployment: loadPinnedCreationProfile(p.document, p.digest).deployment }));
	if (profiles.length > 32 || new Set(profiles.map((p) => `${p.environment}:${p.pin.digest}`)).size !== profiles.length) throw new Error('Invalid creation catalog');
	const observe = dependencies.requireFreshDeployment, quote = dependencies.quoteGas, automaticCap = dependencies.automaticGasCap;
	return async function route(request: Request, env: AuthBindings, manifest: Environment): Promise<Response> {
		let config: Environment;
		try { config = validateIdentityConfig(env, manifest); }
		catch { return v3Json(503, { error_code: 'SERVICE_UNAVAILABLE' }); }
		const url = new URL(request.url), origin = request.headers.get('Origin');
		if (url.origin !== config.api_origin || origin !== config.web_origin || !config.webauthn_allowed_origins.includes(origin)) return v3Json(403, { error_code: 'ORIGIN_NOT_ALLOWED' });
		const respond = (status: number, body: object) => v3Json(status, body, origin);
		const match = PATH.exec(url.pathname);
		if (!match || url.search) return respond(404, { error_code: 'NOT_FOUND' });
		let id; try { id = parseResourceId('operation', match[1]); } catch { return respond(404, { error_code: 'NOT_FOUND' }); }
		const methods = match[2] ? ['POST'] : ['GET', 'POST'];
		const methodResponse = allowMethods(request, origin, methods, headers);
		if (methodResponse) return methodResponse;
		const reading = request.method === 'GET';
		const incompatible = requireCurrentProtocol(request, config, reading ? 'identity' : 'account', profiles.map(p => p.deployment.manifest_id));
		if (incompatible) return incompatible;
		if (!reading && !isJsonRequest(request)) return respond(400, { error_code: 'INVALID_CREATION_REQUEST' });
		const available = profiles.filter((p) => p.environment === config.environment && (reading ||
			(config.wallet_enabled.includes(p.deployment.network_id) && request.headers.get(CLIENT_RELEASE_HEADERS.generation) === String(p.deployment.generation)
				&& request.headers.get(CLIENT_RELEASE_HEADERS.manifest) === p.deployment.manifest_id)));
		if (!reading && !available.length) return respond(503, { error_code: 'PROFILE_UNAVAILABLE' });
		const signal = AbortSignal.any([request.signal, AbortSignal.timeout(15_000)]);
		try {
			const principal = await verifyAppSession(request, env, { rpId: config.webauthn_rp_id, origin: config.web_origin }, dependencies.accessProfiles);
			await new WalletRepository(env.WALLET_DB, principal).getSession(); signal.throwIfAborted();
			const scope = { rpId: config.webauthn_rp_id, origin }, pins = available.map((p) => p.pin);
			const repo = new CreationOperationRepository(env.WALLET_DB, principal, scope, pins);
			if (reading) { const result = await repo.preview(id); signal.throwIfAborted(); return respond(200, result); }
			let body: unknown;
			try { body = await readJsonBounded<unknown>(new Response(request.body, { headers: request.headers }), 8192,
				AbortSignal.any([signal, AbortSignal.timeout(5000)])); }
			catch (error) { return respond(error instanceof ResponseBodyTooLargeError ? 413 : 400, { error_code: 'INVALID_CREATION_REQUEST' }); }
			let cap: bigint | undefined, proof;
			const automatic = !match[2] && body !== null && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).length === 0;
			try { if (match[2]) proof = parseInitializationProof(body); else if (!automatic) cap = parseCreationCapRequest(body); }
			catch { return respond(400, { error_code: 'INVALID_CREATION_REQUEST' }); }
			const initial = await new InitializationRepository(env.WALLET_DB, principal, scope, pins).readAuthorized(id);
			const profile = available.find((p) => p.pin.digest === initial.input.expectedDigest);
			if (!profile) throw new InitializationError('PROFILE_UNAVAILABLE');
			let existing;
			try { existing = await repo.read(id); }
			catch (error) { if (!(error instanceof WalletAccessError) || error.code !== 'NOT_FOUND') throw error; }
			signal.throwIfAborted();
			if (!match[2]) {
				if (existing) {
					// A lost response cannot silently obtain another price or signing digest.
					if (!automatic && existing.terms.maximumGasCharge !== cap) throw new CreationOperationError('CREATION_CONFLICT');
				} else {
					if (Math.floor(Date.now() / 1000) >= initial.input.validUntil) throw new CreationOperationError('CREATION_EXPIRED');
					if (automatic) {
						if (!automaticCap) throw new Error('Automatic creation quote unavailable');
						const admitted = await abortable(automaticCap(profile.pin, initial, signal), signal); signal.throwIfAborted();
						if (typeof admitted !== 'bigint') throw new Error('Invalid automatic creation cap');
						cap = parseCreationCapRequest({ maximum_gas_charge: admitted.toString() });
					}
					await abortable(observe(profile.pin, signal), signal); signal.throwIfAborted();
					let terms = await abortable(quote(profile.pin, initial, cap!, signal), signal); signal.throwIfAborted();
					if (terms.maximumGasCharge !== cap) throw new Error('Quote changed approved cap');
					if ([terms.verificationGasLimit, terms.callGasLimit, terms.preVerificationGas, terms.maxFeePerGas]
						.every((value) => typeof value === 'bigint' && value > 0n && value < (1n << 120n))
						&& (terms.verificationGasLimit + terms.callGasLimit + terms.preVerificationGas) * terms.maxFeePerGas > cap!) {
						// A small user cap is not provider downtime and is never raised silently.
						return respond(automatic ? 503 : 422, { error_code: automatic ? 'CREATION_UNAVAILABLE' : 'CREATION_CAP_TOO_LOW' });
					}
					const sponsor = dependencies.sponsor?.(profile.pin, env.WALLET_DB, principal, signal);
                    if (sponsor) {
                      const now = Math.floor(Date.now() / 1000);
                      terms = { ...terms, sponsorship: sponsor.terms(initial.input.validAfter, initial.input.validUntil) };
                      const candidate = prepareCreationOperation(initial.input, initial.initialProof, terms, now);
                      terms = { ...terms, sponsorship: await sponsor.authorize(candidate.operation, candidate.plan.validAfter, candidate.plan.validUntil) };
                    }
                    await repo.prepare(id, terms);
				}
				const result = await repo.preview(id); signal.throwIfAborted(); return respond(200, result);
			}
			if (!existing) throw new WalletAccessError('NOT_FOUND');
			if (existing.state !== 'authorized') {
				if (existing.authorization_expired) throw new CreationOperationError('CREATION_EXPIRED');
				await abortable(observe(profile.pin, signal), signal); signal.throwIfAborted();
			}
			// Exact signed retries are readbacks; repository still verifies both proofs and
			// compares the winning signature. No fresh RPC or second outbox is needed.
			const result = await repo.authorize(id, proof!); signal.throwIfAborted(); return respond(200, result);
		} catch (error) {
			if (error instanceof Error && error.message === 'Creation exceeds approved gas cap') return respond(422, { error_code: 'CREATION_CAP_TOO_LOW' });
			if (error instanceof Error && error.message === 'SPONSOR_BUDGET_EXHAUSTED') return respond(429, { error_code: error.message });
			if (error instanceof CreationOperationError) return respond({ CREATION_EXPIRED: 410, CREATION_CONFLICT: 409, INVALID_CREATION_ASSERTION: 400 }[error.code], { error_code: error.code });
			if (error instanceof InitializationError) return respond({ PROFILE_UNAVAILABLE: 503, INITIALIZATION_EXPIRED: 410,
				INITIALIZATION_CONFLICT: 409, INITIALIZATION_LIMIT: 429, INITIALIZATION_REQUIRED: 409, INVALID_INITIALIZATION_ASSERTION: 400 }[error.code], { error_code: error.code });
			if (error instanceof IdentityError) return respond(error.code === 'UNAUTHENTICATED' ? 401 : 503, { error_code: error.code });
			if (error instanceof WalletAccessError) return respond({ UNAUTHENTICATED: 401, SESSION_REQUIRED: 409, NOT_FOUND: 404, WALLET_DATA_INVALID: 503 }[error.code], { error_code: error.code });
			return respond(503, { error_code: 'CREATION_UNAVAILABLE' });
		}
	};
}
