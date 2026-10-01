import { sha256, stringToHex } from 'viem';
import type { Principal } from '../src/auth/principal';

export function testUserId(label: string) {
  if (/^usr_[0-9a-f-]{36}$/.test(label)) return label;
  const hash = sha256(stringToHex(label)).slice(2);
  return `usr_${hash.slice(0, 8)}-${hash.slice(8, 12)}-4${hash.slice(13, 16)}-8${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
}
export const testCredentialRef = (label: string) => `op_${testUserId(label).slice(4)}`;
export function testPrincipal(label: string, overrides: Partial<Principal> = {}): Principal {
  const now = Math.floor(Date.now() / 1000), userId = testUserId(label);
  return { environment: 'staging', userId, credentialRef: testCredentialRef(userId), accessVersion: 1,
    authTime: now - 30, expiresAt: now + 3600, ...overrides };
}
