import { z } from 'zod';

const page = { after: z.string().uuid().optional(), limit: z.number().int().min(1).max(100).optional() };
export const OwnerConsoleOperationSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('accounts.list'), ...page }).strict(),
  z.object({ type: z.literal('conversations.list'), ...page }).strict(),
  z.object({ type: z.literal('conversation.read'), chat_id: z.string().uuid(), after_revision: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(), limit: z.number().int().min(1).max(100).optional() }).strict(),
  z.object({ type: z.literal('account.recover'), user_id: z.string().uuid(), new_password: z.string().min(15).max(256), new_key_id: z.string().uuid().optional(), new_public_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional() }).strict(),
]).refine(op => op.type !== 'account.recover' || Boolean(op.new_key_id) === Boolean(op.new_public_key), 'Replacement key id and public key must be supplied together');
export type OwnerConsoleOperation = z.infer<typeof OwnerConsoleOperationSchema>;
export const OwnerConsolePrepareSchema = z.object({ owner_key_id: z.string().uuid(), operation: OwnerConsoleOperationSchema }).strict();
export const OwnerConsoleCompleteSchema = z.object({ challenge_id: z.string().uuid(), signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/), operation: OwnerConsoleOperationSchema }).strict();
export type OwnerConsoleComplete = z.infer<typeof OwnerConsoleCompleteSchema>;
export type OwnerConsoleChallenge = {
  challenge_id: string; challenge: string; purpose: 'OWNER_CONSOLE'; key_id: string;
  owner_user_id: string; workspace_id: string; origin: string; operation_digest: string; expires_at: string;
};
/** Protocol values contain strings, safe integers, arrays and objects only. */
export function canonicalOwnerJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalOwnerJson).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => `${JSON.stringify(key)}:${canonicalOwnerJson(item)}`).join(',')}}`;
  return JSON.stringify(value);
}
export function ownerConsoleSignatureMessage(challenge: OwnerConsoleChallenge): Uint8Array {
  return new TextEncoder().encode(canonicalOwnerJson(challenge));
}
