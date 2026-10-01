import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const fixture = JSON.parse(readFileSync(new URL(import.meta.resolve('@gatopago/shared/fixtures/v3-webauthn-chromium.json')), 'utf8')) as {
  challenge: string; rpId: string; origin: string; spki: string; algorithm: number;
  authenticatorData: string; clientDataJSON: string; signatureDER: string;
  r: string; sRaw: string; sNormalized: string;
};
const bytes = (hex: string) => Buffer.from(hex.slice(2), 'hex');
const sha256 = (data: string | Buffer) => createHash('sha256').update(data).digest();
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

describe('V3 public Chromium WebAuthn assertion', () => {
  it('independently verifies the original DER signature using Node/OpenSSL', () => {
    const key = createPublicKey({ key: bytes(fixture.spki), format: 'der', type: 'spki' });
    const payload = Buffer.concat([bytes(fixture.authenticatorData), sha256(fixture.clientDataJSON)]);
    expect(fixture.algorithm).toBe(-7);
    expect(key.asymmetricKeyDetails?.namedCurve).toBe('prime256v1');
    expect(verify('sha256', payload, key, bytes(fixture.signatureDER))).toBe(true);
    payload[0] ^= 1;
    expect(verify('sha256', payload, key, bytes(fixture.signatureDER))).toBe(false);
  });

  it('binds the exact browser origin, RP, challenge and UV without inventing a credential', () => {
    const client = JSON.parse(fixture.clientDataJSON) as Record<string, unknown>;
    expect(client).toEqual({ type: 'webauthn.get', challenge: bytes(fixture.challenge).toString('base64url'),
      origin: fixture.origin, crossOrigin: false });
    expect(bytes(fixture.authenticatorData).subarray(0, 32)).toEqual(sha256(fixture.rpId));
    expect(bytes(fixture.authenticatorData)[32] & 5).toBe(5);
  });

  it('retains the captured high-S DER and proves the normalization used by Solidity', () => {
    const der = bytes(fixture.signatureDER);
    // This exact captured vector has 32-byte R and a positive 33-byte S. Not a production DER parser.
    expect(der.length).toBe(71);
    expect(der.subarray(0, 4).toString('hex')).toBe('30450220');
    expect(der.subarray(4, 36)).toEqual(bytes(fixture.r));
    expect(der.subarray(36, 39).toString('hex')).toBe('022100');
    expect(der.subarray(39)).toEqual(bytes(fixture.sRaw));
    expect(BigInt(fixture.sRaw)).toBeGreaterThan(order / 2n);
    expect(BigInt(fixture.sNormalized)).toBe(order - BigInt(fixture.sRaw));
    expect(BigInt(fixture.sNormalized)).toBeLessThanOrEqual(order / 2n);
  });
});
