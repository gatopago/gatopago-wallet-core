export function rpcEndpoint(value: string) {
	const url = new URL(value);
	if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error('Invalid RPC provider URL');
	return url.href;
}
export interface RpcProvider { readonly operatorId: string; readonly url: string }
export function validateRpcProviders(providers: readonly RpcProvider[]) {
 if (providers.length !== 2) throw new Error('RPC_PROVIDERS_INVALID');
 const peers = providers.map((p) => {
  if (!/^[a-z0-9][a-z0-9-]{2,63}$(?![\s\S])/.test(p.operatorId)) throw new Error('RPC_PROVIDERS_INVALID');
  return Object.freeze({ operatorId: p.operatorId, url: rpcEndpoint(p.url) });
 });
 if (peers[0].operatorId === peers[1].operatorId || new URL(peers[0].url).hostname === new URL(peers[1].url).hostname) throw new Error('RPC_PROVIDERS_INVALID');
 return Object.freeze(peers);
}
