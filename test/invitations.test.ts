import { describe, expect, it } from 'vitest';
import { invitationCode } from '../src/auth/invitations';

describe('operator-defined invitation text', () => {
  it.each(['123', 'daniel', 'team1', 'a', 'hello world', "O'Brien", 'café 🐈', ' padded ', 'x'.repeat(120)])('preserves %s without format restrictions or normalization', code => {
      expect(invitationCode(code)).toBe(code);
    });
  it.each([undefined, null, 123, {}, [], ''])('rejects missing or non-text code %s', code => {
    expect(() => invitationCode(code)).toThrow('INVITE_UNAVAILABLE');
  });
});
