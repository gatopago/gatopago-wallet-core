import { RegistrationError } from './profile';

export function invitationCode(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0)
    throw new RegistrationError('INVITE_UNAVAILABLE');
  return value;
}
