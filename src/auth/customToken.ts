import { importPKCS8, SignJWT } from 'jose';
import { parseResourceId } from '@gatopago/shared/v3/primitives';

export async function createSessionToken(
  signerJson: string,
  projectId: string,
  principal: { userId: string; credentialRef: string; accessVersion: number },
) {
  const signer: unknown = JSON.parse(signerJson);
  if (
    !signer ||
    typeof signer !== 'object' ||
    !('project_id' in signer) ||
    signer.project_id !== projectId ||
    !('client_email' in signer) ||
    typeof signer.client_email !== 'string' ||
    !signer.client_email.endsWith(`@${projectId}.iam.gserviceaccount.com`) ||
    !/^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/.test(signer.client_email) ||
    !('private_key' in signer) ||
    typeof signer.private_key !== 'string' ||
    !Number.isSafeInteger(principal.accessVersion) ||
    principal.accessVersion < 1
  )
    throw new Error('Invalid Firebase signer');
  const userId = parseResourceId('user', principal.userId),
    credential = parseResourceId('operation', principal.credentialRef);
  const key = await importPKCS8(signer.private_key, 'RS256');
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    uid: userId,
    claims: { credential_ref: credential, access_version: principal.accessVersion },
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
    .setIssuer(signer.client_email)
    .setSubject(signer.client_email)
    .setAudience(
      'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    )
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}
