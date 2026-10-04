import {
  isLocalEnvironment,
  environmentFromVariables,
  parseEnvironment,
  type Environment,
  type EnvironmentVariables,
} from '@gatopago/environment';

export type AuthBindings = Pick<
  WalletCoreV3Bindings,
  | 'WALLET_DB'
  | 'GATOPAGO_ENVIRONMENT'
  | 'FIREBASE_PROJECT_ID'
  | 'FIREBASE_CUSTOM_TOKEN_SIGNER_JSON'
  | 'TURNSTILE_SECRET_KEY'
  | 'AUTH_RATE_LIMIT_PEPPER'
  | 'AUTH_IP_REQUESTS_PER_HOUR'
  | 'AUTH_GLOBAL_REQUESTS_PER_HOUR'
> &
  EnvironmentVariables;

export function configuredEnvironment(env: AuthBindings): Environment {
  return environmentFromVariables(env);
}

export function validateAuthConfig(env: AuthBindings, input: Environment): Environment {
  const config = validateIdentityConfig(env, input);
  if (
    !env.FIREBASE_CUSTOM_TOKEN_SIGNER_JSON ||
    !env.TURNSTILE_SECRET_KEY ||
    env.TURNSTILE_SECRET_KEY.trim().length < 20 ||
    (/^[123]x0{10}/.test(env.TURNSTILE_SECRET_KEY) && !isLocalEnvironment(config)) ||
    !env.AUTH_RATE_LIMIT_PEPPER ||
    env.AUTH_RATE_LIMIT_PEPPER.trim().length < 32
  )
    throw new Error('V3 authentication is not provisioned');
  authLimit(env.AUTH_IP_REQUESTS_PER_HOUR);
  authLimit(env.AUTH_GLOBAL_REQUESTS_PER_HOUR);
  return config;
}

export function authLimit(value: string): number {
  if (!/^[1-9][0-9]{0,6}$/.test(value)) throw new Error('Invalid authentication quota');
  return Number(value);
}

export function validateIdentityConfig(env: AuthBindings, input: Environment): Environment {
  const config = parseEnvironment(input);
  if (
    config.environment !== env.GATOPAGO_ENVIRONMENT ||
    config.status !== 'provisioned' ||
    !config.firebase_project_id ||
    config.firebase_project_id.startsWith('demo-') ||
    env.FIREBASE_PROJECT_ID !== config.firebase_project_id ||
    !env.WALLET_DB
  )
    throw new Error('V3 authentication is not provisioned');
  return config;
}
