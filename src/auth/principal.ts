import type { Environment } from '@gatopago/environment';

export interface Principal {
  readonly environment: Environment['environment'];
  readonly userId: string;
  readonly authTime: number;
  readonly expiresAt: number;
  readonly credentialRef: string;
  readonly accessVersion: number;
}
