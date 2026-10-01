export class RegistrationError extends Error {
  constructor(readonly code: 'INVALID_REGISTRATION' | 'INVITE_UNAVAILABLE' | 'USERNAME_UNAVAILABLE' | 'CHALLENGE_UNAVAILABLE') {
    super(code); this.name = 'RegistrationError';
  }
}

const reserved = new Set(['gatopago', 'admin', 'administrator', 'support', 'soporte', 'security',
  'login', 'logout', 'signup', 'register', 'settings', 'account', 'wallet', 'wallets',
  'payment', 'payments', 'checkout', 'receive', 'privacy', 'terms', 'profile', 'status']);

export function registrationProfile(name: unknown, handle: unknown) {
  if (typeof name !== 'string' || typeof handle !== 'string') throw new RegistrationError('INVALID_REGISTRATION');
  const displayName = normalizeDisplayName(name), username = handle.trim().toLowerCase();
  if (!/^[a-z][a-z0-9_]{4,29}$/.test(username)) throw new RegistrationError('INVALID_REGISTRATION');
  if (reserved.has(username)) throw new RegistrationError('USERNAME_UNAVAILABLE');
  return { displayName, username };
}

export function normalizeDisplayName(value: unknown): string {
  if (typeof value !== 'string') throw new RegistrationError('INVALID_REGISTRATION');
  const name = value.normalize('NFC').trim();
  if (!name || name.length > 80 || /[\p{Cc}\p{Cf}]/u.test(name)) throw new RegistrationError('INVALID_REGISTRATION');
  return name;
}
