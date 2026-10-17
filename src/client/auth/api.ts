import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import type { IDBPDatabase } from 'idb';
import { z } from 'zod';
import { PasswordLoginResponseSchema, type PasswordLoginResponse } from '../../shared/contracts/passwords';
import { PortableKeyChallengeResponseSchema, PortableKeyLoginResponseSchema } from '../../shared/contracts/portable-keys';
import { CurrentSessionResponseSchema, UpdateStaffDisplayNameResponseSchema, type CurrentSessionResponse } from '../../shared/contracts/session';
import { uuidv7 } from '../../shared/ids/uuidv7';
import { generateDeviceIdentity, persistGeneratedDeviceIdentity, disposeDeviceIdentity } from '../crypto/key-vault/identity';
import { bytesToBase64Url } from '../crypto/local-state/base64url';
import type { LocalDbSchema } from '../storage/schema';
import { ApiError, apiFetch } from '../transport/api';
import { disposePortableKey, signPortableChallenge, unlockPortableKey } from './portable-key';
import { solvePasswordChallenge } from './admission-proof';

const CeremonyOptionsSchema = z.object({
  challenge_id: z.string().uuid(),
  options: z.unknown(),
});
const RegistrationOptionsSchema = CeremonyOptionsSchema.extend({ device_id: z.string().uuid() });
const LoginResultSchema = z.object({
  session_id: z.string().min(1),
  user_id: z.string().uuid(),
  device_id: z.string().uuid(),
  device_state: z.enum(['AUTHORIZED', 'PENDING']),
});
const ReauthResultSchema = z.object({ verified: z.literal(true), verified_at: z.string().datetime() });

type AuthenticationOptions = Parameters<typeof startAuthentication>[0]['optionsJSON'];
type RegistrationOptions = Parameters<typeof startRegistration>[0]['optionsJSON'];

export type PreparedExistingLogin = { challenge_id: string; options: AuthenticationOptions; device_id: string };
export type PreparedNewDeviceLogin = {
  challenge_id: string;
  options: AuthenticationOptions;
  device_id: string;
  display_name: string;
  crypto_identity_public_key: string;
};
export type PreparedNewPasskey = PreparedNewDeviceLogin;
export type PreparedAccessRegistration = { challenge_id: string; options: RegistrationOptions; device_id: string };
export type PreparedReauthentication = { challenge_id: string; options: AuthenticationOptions };

export async function getCurrentSession(): Promise<CurrentSessionResponse> {
  return apiFetch('/api/v1/sessions/current', {}, (value) => CurrentSessionResponseSchema.parse(value));
}

export async function updateStaffDisplayName(workspaceId: string, displayName: string) {
  return apiFetch('/api/v1/sessions/current/display-name', {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ workspace_id: workspaceId, display_name: displayName }),
  }, (value) => UpdateStaffDisplayNameResponseSchema.parse(value), { retryMode: 'none' });
}

const PasswordChallengeSchema = z.object({
  protocol: z.literal('ratchet-auth-work-v1'), challenge_id: z.string().uuid(),
  challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  difficulty: z.number().int().min(18).max(22), expires_at: z.number().int().positive(),
});

async function passwordLogin(body: Record<string, unknown>, signal?: AbortSignal, path='/api/v1/auth/password/login'): Promise<PasswordLoginResponse> {
  const send = (payload: Record<string, unknown>) => apiFetch(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload), ...(signal ? { signal } : {}),
  }, value => PasswordLoginResponseSchema.parse(value), { retryMode: 'none', timeoutMs: 30_000 });
  try { return await send(body); }
  catch (error) {
    if (!(error instanceof ApiError) || error.type !== 'AUTHENTICATION_PROOF_REQUIRED') throw error;
    const challenge = await apiFetch('/api/v1/auth/password/challenge', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ login_name: body.login_name }), ...(signal ? { signal } : {}),
    }, value => PasswordChallengeSchema.parse(value), { retryMode: 'none' });
    const proof = await solvePasswordChallenge(challenge, signal);
    // The proof authorizes one additional admission, never an automatic retry
    // after credential verification or a bypass of the hard request budget.
    return send({ ...body, proof });
  }
}

export async function passwordLoginExisting(loginName: string, password: string, deviceId: string, signal?: AbortSignal): Promise<PasswordLoginResponse> {
  return passwordLogin({ login_name: loginName, password, device: { mode: 'existing', device_id: deviceId } }, signal);
}

export async function passwordLoginNewDevice(
  db: IDBPDatabase<LocalDbSchema>,
  loginName: string,
  password: string,
  deviceName: string,
): Promise<PasswordLoginResponse> {
  const deviceId = uuidv7();
  const generated = await generateDeviceIdentity();
  let persisted = false;
  try {
    await persistGeneratedDeviceIdentity(db, deviceId, generated);
    persisted = true;
    return await passwordLogin({
      login_name: loginName,
      password,
      device: {
        mode: 'new', device_id: deviceId, display_name: deviceName,
        crypto_identity_public_key: bytesToBase64Url(generated.keyPair.publicKey),
      },
    });
  } catch (error) {
    if (persisted) await db.delete('device_identity', deviceId).catch(() => undefined);
    throw error;
  } finally {
    disposeDeviceIdentity(generated);
  }
}

export async function activatePasswordAccess(
  db: IDBPDatabase<LocalDbSchema>,
  accessToken: string,
  loginName: string,
  password: string,
  deviceName: string,
): Promise<PasswordLoginResponse> {
  const deviceId = uuidv7();
  const generated = await generateDeviceIdentity();
  let persisted = false;
  try {
    await persistGeneratedDeviceIdentity(db, deviceId, generated);
    persisted = true;
    return await passwordLogin({
      access_token: accessToken, login_name: loginName, password,
      device: {
        mode: 'new', device_id: deviceId, display_name: deviceName,
        crypto_identity_public_key: bytesToBase64Url(generated.keyPair.publicKey),
      },
    }, undefined, '/api/v1/auth/password/activate');
  } catch (error) {
    if (persisted) await db.delete('device_identity', deviceId).catch(() => undefined);
    throw error;
  } finally {
    disposeDeviceIdentity(generated);
  }
}

export async function passwordReauthenticate(password: string) {
  return apiFetch('/api/v1/auth/password/reauth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  }, (value) => ReauthResultSchema.parse(value), { retryMode: 'none' });
}

export async function portableKeyLoginExisting(file: File, password: string, deviceId: string) {
  const key = await unlockPortableKey(file, password);
  try {
    const challenge = await portableKeyLoginPrepare(key.keyId, { mode: 'existing', device_id: deviceId });
    return await portableKeyLoginComplete(challenge.challenge_id, signPortableChallenge(key, challenge));
  } finally {
    disposePortableKey(key);
  }
}

export async function portableKeyLoginNewDevice(
  db: IDBPDatabase<LocalDbSchema>, file: File, password: string, deviceName: string,
) {
  const key = await unlockPortableKey(file, password);
  const deviceId = uuidv7();
  const generated = await generateDeviceIdentity();
  let persisted = false;
  try {
    await persistGeneratedDeviceIdentity(db, deviceId, generated);
    persisted = true;
    const challenge = await portableKeyLoginPrepare(key.keyId, {
      mode: 'new', device_id: deviceId, display_name: deviceName,
      crypto_identity_public_key: bytesToBase64Url(generated.keyPair.publicKey),
    });
    return await portableKeyLoginComplete(challenge.challenge_id, signPortableChallenge(key, challenge));
  } catch (error) {
    if (persisted) await db.delete('device_identity', deviceId).catch(() => undefined);
    throw error;
  } finally {
    disposePortableKey(key);
    disposeDeviceIdentity(generated);
  }
}

async function portableKeyLoginPrepare(key_id: string, device: Record<string, unknown>) {
  return apiFetch('/api/v1/auth/portable-key/login/prepare', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key_id, device }),
  }, (value) => PortableKeyChallengeResponseSchema.parse(value), { retryMode: 'none' });
}

async function portableKeyLoginComplete(challenge_id: string, signature: string) {
  return apiFetch('/api/v1/auth/portable-key/login/complete', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challenge_id, signature }),
  }, (value) => PortableKeyLoginResponseSchema.parse(value), { retryMode: 'none' });
}

export async function prepareExistingLogin(deviceId: string): Promise<PreparedExistingLogin> {
  const response = await authenticationOptions();
  return { challenge_id: response.challenge_id, options: response.options as AuthenticationOptions, device_id: deviceId };
}

export async function completeExistingLogin(prepared: PreparedExistingLogin) {
  const credential = await startAuthentication({ optionsJSON: prepared.options });
  return apiFetch('/api/v1/auth/passkey/login/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge_id: prepared.challenge_id, response: credential, device: { mode: 'existing', device_id: prepared.device_id } }),
  }, (value) => LoginResultSchema.parse(value), { retryMode: 'none' });
}

export async function prepareNewDeviceLogin(
  db: IDBPDatabase<LocalDbSchema>,
  deviceName: string,
): Promise<PreparedNewDeviceLogin> {
  const deviceId = uuidv7();
  const generated = await generateDeviceIdentity();
  try {
    const response = await authenticationOptions();
    await persistGeneratedDeviceIdentity(db, deviceId, generated);
    return {
      challenge_id: response.challenge_id,
      options: response.options as AuthenticationOptions,
      device_id: deviceId,
      display_name: deviceName,
      crypto_identity_public_key: bytesToBase64Url(generated.keyPair.publicKey),
    };
  } finally {
    disposeDeviceIdentity(generated);
  }
}

export async function completeNewDeviceLogin(prepared: PreparedNewDeviceLogin) {
  const credential = await startAuthentication({ optionsJSON: prepared.options });
  return apiFetch('/api/v1/auth/passkey/login/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      challenge_id: prepared.challenge_id,
      response: credential,
      device: {
        mode: 'new',
        device_id: prepared.device_id,
        display_name: prepared.display_name,
        crypto_identity_public_key: prepared.crypto_identity_public_key,
      },
    }),
  }, (value) => LoginResultSchema.parse(value), { retryMode: 'none' });
}

export async function prepareAccessRegistration(
  db: IDBPDatabase<LocalDbSchema>,
  accessToken: string,
  deviceName: string,
): Promise<PreparedAccessRegistration> {
  const generated = await generateDeviceIdentity();
  try {
    const response = await apiFetch('/api/v1/auth/passkey/register/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        access_token: accessToken,
        device_name: deviceName,
        crypto_identity_public_key: bytesToBase64Url(generated.keyPair.publicKey),
      }),
    }, (value) => RegistrationOptionsSchema.parse(value), { retryMode: 'none' });
    await persistGeneratedDeviceIdentity(db, response.device_id, generated);
    return { challenge_id: response.challenge_id, device_id: response.device_id, options: response.options as RegistrationOptions };
  } finally {
    disposeDeviceIdentity(generated);
  }
}

export async function completeAccessRegistration(prepared: PreparedAccessRegistration) {
  const credential = await startRegistration({ optionsJSON: prepared.options });
  return apiFetch('/api/v1/auth/passkey/register/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge_id: prepared.challenge_id, response: credential }),
  }, (value) => LoginResultSchema.parse(value), { retryMode: 'none' });
}

export async function prepareReauthentication(): Promise<PreparedReauthentication> {
  const response = await apiFetch('/api/v1/auth/passkey/reauth/options', { method: 'POST' }, (value) => CeremonyOptionsSchema.parse(value), { retryMode: 'none' });
  return { challenge_id: response.challenge_id, options: response.options as AuthenticationOptions };
}

export async function completeReauthentication(prepared: PreparedReauthentication) {
  const credential = await startAuthentication({ optionsJSON: prepared.options });
  return apiFetch('/api/v1/auth/passkey/reauth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge_id: prepared.challenge_id, response: credential }),
  }, (value) => ReauthResultSchema.parse(value), { retryMode: 'none' });
}

export async function portableKeyReauthenticate(file: File, password: string) {
  const key = await unlockPortableKey(file, password);
  try {
    const challenge = await apiFetch('/api/v1/auth/portable-key/reauth/prepare', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key_id: key.keyId }),
    }, (value) => PortableKeyChallengeResponseSchema.parse(value), { retryMode: 'none' });
    return apiFetch('/api/v1/auth/portable-key/reauth/complete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_id: challenge.challenge_id, signature: signPortableChallenge(key, challenge) }),
    }, (value) => ReauthResultSchema.parse(value), { retryMode: 'none' });
  } finally {
    disposePortableKey(key);
  }
}

export async function logout(): Promise<void> {
  try {
    await apiFetch('/api/v1/auth/logout', { method: 'POST' }, () => undefined, { retryMode: 'none' });
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.type === 'DEVICE_REVOKED')) return;
    throw error;
  }
}

async function authenticationOptions() {
  return apiFetch('/api/v1/auth/passkey/login/options', { method: 'POST' }, (value) => CeremonyOptionsSchema.parse(value), { retryMode: 'none' });
}
