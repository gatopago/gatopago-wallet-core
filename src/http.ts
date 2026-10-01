export function v3Json(status: number, body: object, origin?: string): Response {
  const headers = new Headers({ 'Cache-Control': 'no-store', 'CDN-Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'Vary': 'Origin',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'" });
  if (origin) headers.set('Access-Control-Allow-Origin', origin);
  if (status === 429 || status === 503) headers.set('Retry-After', '60');
  return Response.json(body, { status, headers });
}

/** Call after origin and resource validation, before authentication or mutation. */
export function allowMethods(request: Request, origin: string, methods: readonly string[], headers: readonly string[]): Response | null {
  if (request.method === 'OPTIONS') {
    const requested = (request.headers.get('Access-Control-Request-Headers') ?? '').toLowerCase()
      .split(',').map(header => header.trim()).filter(Boolean);
    if (!methods.includes(request.headers.get('Access-Control-Request-Method') ?? '')
      || requested.some(header => !headers.some(allowed => allowed.toLowerCase() === header))) {
      return v3Json(403, { error_code: 'CORS_NOT_ALLOWED' }, origin);
    }
    const response = v3Json(200, {}, origin);
    response.headers.set('Access-Control-Allow-Methods', methods.join(', '));
    response.headers.set('Access-Control-Allow-Headers', headers.join(', '));
    response.headers.set('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
    return response;
  }
  if (!methods.includes(request.method)) {
    const response = v3Json(405, { error_code: 'METHOD_NOT_ALLOWED' }, origin);
    response.headers.set('Allow', [...methods, 'OPTIONS'].join(', '));
    return response;
  }
  return null;
}

export function isJsonRequest(request: Request): boolean {
  return /^application\/json(?:\s*;\s*charset=utf-8)?$(?![\s\S])/i.test(request.headers.get('Content-Type') ?? '');
}
