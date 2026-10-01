import { sha256, stringToHex } from 'viem';
import { RegistrationError } from './profile';

export function invitationHash(token: unknown) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw new RegistrationError('INVITE_UNAVAILABLE');
  return sha256(stringToHex(token));
}
