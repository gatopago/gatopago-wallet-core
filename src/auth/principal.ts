import type { Environment } from '@gatopago/environment';

/** Application identity after token verification. Provider claims stay in auth. */
export interface Principal {
  readonly environment: Environment['environment'];
  readonly userId: string;
  readonly authTime: number;
  readonly expiresAt: number;
  readonly credentialRef: string;
  readonly accessVersion: number;
}
