import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decodeAbiParameters, hexToBytes, type Hex } from 'viem';
import {
  assertWebAuthnScope,
  encodeWebAuthnAssertion,
  normalizeWebAuthnSignature,
  webAuthnKeyFromSpki,
  WebAuthnEncodingError,
} from '@gatopago/shared/v3/webauthn';

const captured = JSON.parse(
  readFileSync(
    new URL(import.meta.resolve('@gatopago/shared/fixtures/v3-webauthn-chromium.json')),
    'utf8',
  ),
) as {
  challenge: Hex;
  rpId: string;
  origin: string;
  spki: Hex;
  authenticatorData: Hex;
  clientDataJSON: string;
  signatureDER: Hex;
  r: Hex;
  sNormalized: Hex;
};
const bytes = (hex: Hex) => hexToBytes(hex);
const text = (value: string) => new TextEncoder().encode(value);
const scope = { rpId: captured.rpId, origin: captured.origin };
const key = webAuthnKeyFromSpki(scope, bytes(captured.spki));
const input = () => ({
  scope,
  key,
  challenge: captured.challenge,
  response: {
    authenticatorData: bytes(captured.authenticatorData),
    clientDataJSON: text(captured.clientDataJSON),
    signatureDER: bytes(captured.signatureDER),
  },
});
const abi = [
  { type: 'bytes32' },
  { type: 'bytes32' },
  { type: 'uint256' },
  { type: 'uint256' },
  { type: 'bytes' },
  { type: 'string' },
] as const;

describe('V3 WebAuthn encoding against the actual verifier profile', () => {
  it('encodes the real captured Chromium assertion without an outer tuple offset', () => {
    const signature = encodeWebAuthnAssertion(input());
    expect(decodeAbiParameters(abi, signature)).toEqual([
      captured.r,
      captured.sNormalized,
      23n,
      1n,
      captured.authenticatorData,
      captured.clientDataJSON,
    ]);
    expect(signature.slice(0, 66)).toBe(captured.r);
    expect(key.length).toBe(258);
  });
  it('normalizes high-S without changing R or signed bytes', () => {
    const value = input();
    const before = structuredClone(value);
    expect(normalizeWebAuthnSignature(value.response.signatureDER)).toEqual({
      r: captured.r,
      s: captured.sNormalized,
    });
    encodeWebAuthnAssertion(value);
    expect(value).toEqual(before);
  });
  it.each([
    { rpId: 'gatopago.com', origin: 'https://gatopago.com' },
    { rpId: 'gatopago.com', origin: 'https://app.gatopago.com' },
    { rpId: 'wallet.example.org', origin: 'https://wallet.example.org' },
    scope,
  ])('accepts a canonical scope (%j); allowlisting remains the caller responsibility', (value) => {
    expect(() => assertWebAuthnScope(value)).not.toThrow();
  });
  it.each([
    ['127.0.0.1', 'http://127.0.0.1:3000'],
    ['gatopago.com', 'http://gatopago.com'],
    ['gatopago.com', 'https://gatopago.com.evil.test'],
    ['gatopago.com', 'https://evilgatopago.com'],
    ['gatopago.com', 'https://gatopago.com/'],
    ['gatopago.com', 'https://gatopago.com?q=1'],
    ['gatopago.com', 'https://user@gatopago.com'],
    ['GatoPago.com', 'https://gatopago.com'],
    ['gatopago.com.', 'https://gatopago.com.'],
    ['com', 'https://gatopago.com'],
    ['-bad.com', 'https://-bad.com'],
    ['gatopago.com', 'https://GatoPago.com'],
    ['localhost', 'http://evil.localhost:3000'],
    ['localhost', 'http://localhost:3000/#x'],
  ])('rejects a mismatched/noncanonical scope %s / %s', (rpId, origin) => {
    expect(() => assertWebAuthnScope({ rpId, origin })).toThrow(WebAuthnEncodingError);
  });
  it.each([0, 20, 26, 64, 90, 92, 1000])('rejects unsupported SPKI size %i', (size) => {
    expect(() => webAuthnKeyFromSpki(scope, new Uint8Array(size))).toThrow(WebAuthnEncodingError);
  });
  it('rejects a wrong algorithm, curve and invalid point', () => {
    for (const index of [8, 22, 26, 40]) {
      const spki = bytes(captured.spki);
      spki[index] ^= 1;
      expect(() => webAuthnKeyFromSpki(scope, spki)).toThrow(WebAuthnEncodingError);
    }
    const spki = bytes(captured.spki);
    spki.fill(0, 27);
    expect(() => webAuthnKeyFromSpki(scope, spki)).toThrow(WebAuthnEncodingError);
  });
  it.each(['0x', '0x00', `0x${'00'.repeat(64)}`, `0x${'00'.repeat(128)}`])(
    'rejects invalid/mismatched signer key %s',
    (key) => {
      expect(() => encodeWebAuthnAssertion({ ...input(), key: key as Hex })).toThrow(
        WebAuthnEncodingError,
      );
    },
  );
  it.each([
    '0x',
    `0x${'01'.repeat(31)}`,
    `0x${'01'.repeat(33)}`,
    `0x${'AB'.repeat(32)}`,
    `0x${'01'.repeat(32)}`,
  ])('rejects wrong challenge %s', (challenge) => {
    expect(() => encodeWebAuthnAssertion({ ...input(), challenge: challenge as Hex })).toThrow(
      WebAuthnEncodingError,
    );
  });
  it.each([
    '0x',
    '0x3006020100020101',
    '0x3006020101020100',
    '0x3006020180020101',
    '0x300702020001020101',
    '0x308106020101020101',
    '0x300602010102010100',
    `0x3026022100${'ff'.repeat(32)}020101`,
    '0x3006020101',
    '0x3106020101020101',
  ])('rejects malformed/out-of-range DER %s', (der) => {
    expect(() => normalizeWebAuthnSignature(bytes(der as Hex))).toThrow(WebAuthnEncodingError);
  });
  it('rejects authenticator data bounds, wrong RP, missing UP/UV and impossible BE/BS', () => {
    for (const length of [0, 32, 36, 1025]) {
      const value = input();
      value.response.authenticatorData = new Uint8Array(length);
      expect(() => encodeWebAuthnAssertion(value)).toThrow(WebAuthnEncodingError);
    }
    for (const flags of [0, 1, 4, 0x15]) {
      const value = input();
      value.response.authenticatorData[32] = flags;
      expect(() => encodeWebAuthnAssertion(value)).toThrow(WebAuthnEncodingError);
    }
    const value = input();
    value.response.authenticatorData[0] ^= 1;
    expect(() => encodeWebAuthnAssertion(value)).toThrow('RP mismatch');
  });
  it.each([
    '',
    'x'.repeat(2049),
    captured.clientDataJSON.replace('false', 'true'),
    captured.clientDataJSON.replace('localhost:3000', 'localhost:3001'),
    captured.clientDataJSON.replace('webauthn.get', 'webauthn.create'),
    `{"nested":${captured.clientDataJSON}}`,
    ` ${captured.clientDataJSON}`,
    captured.clientDataJSON.slice(0, -1),
    `${captured.clientDataJSON.slice(0, -1)},"origin":"https://evil.test"}`,
    `${captured.clientDataJSON.slice(0, -1)},"topOrigin":"http://localhost:3000"}`,
    captured.clientDataJSON.replace('localhost', 'local\\u0068ost'),
  ])('rejects mismatched, escaped, nested or invalid client data (%#)', (json) => {
    const value = input();
    value.response.clientDataJSON = text(json);
    expect(() => encodeWebAuthnAssertion(value)).toThrow(WebAuthnEncodingError);
  });
  it('rejects invalid UTF-8, BOM and otherwise well-formed but modified signed data', () => {
    for (const json of [
      new Uint8Array([255]),
      text(`\ufeff${captured.clientDataJSON}`),
      text(`${captured.clientDataJSON.slice(0, -1)},"newField":true}`),
    ]) {
      const value = input();
      value.response.clientDataJSON = json;
      expect(() => encodeWebAuthnAssertion(value)).toThrow(WebAuthnEncodingError);
    }
    const value = input();
    value.response.authenticatorData[36] ^= 1;
    expect(() => encodeWebAuthnAssertion(value)).toThrow('signature');
  });
  it('checks P-256 order boundaries and canonical short/padded DER integers', () => {
    const order = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';
    expect(() => normalizeWebAuthnSignature(bytes(`0x3026022100${order}020101`))).toThrow(
      WebAuthnEncodingError,
    );
    const orderMinusOne = order.slice(0, -1) + '0';
    expect(normalizeWebAuthnSignature(bytes(`0x3026020101022100${orderMinusOne}`))).toEqual({
      r: `0x${'0'.repeat(63)}1`,
      s: `0x${'0'.repeat(63)}1`,
    });
    expect(normalizeWebAuthnSignature(bytes('0x300702020080020101')).r).toBe(
      `0x${'0'.repeat(62)}80`,
    );
  });
  it('differentially checks 32 fresh Node/OpenSSL signatures and extra JSON fields', () => {
    for (let i = 0; i < 32; i++) {
      // Ephemeral test key in memory only. No private key or credential is exported or persisted.
      const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const value = input();
      value.key = webAuthnKeyFromSpki(
        scope,
        pair.publicKey.export({ type: 'spki', format: 'der' }),
      );
      value.response.clientDataJSON = text(
        `${captured.clientDataJSON.slice(0, -1)},"future":{"index":${i}}}`,
      );
      const payload = Buffer.concat([
        value.response.authenticatorData,
        createHash('sha256').update(value.response.clientDataJSON).digest(),
      ]);
      value.response.signatureDER = sign('sha256', payload, pair.privateKey);
      expect(verify('sha256', payload, pair.publicKey, value.response.signatureDER)).toBe(true);
      const encoded = decodeAbiParameters(abi, encodeWebAuthnAssertion(value));
      expect(encoded[5]).toContain('future');
    }
  });
});
