import { z } from 'zod';
import { base64UrlToBytes, bytesToBase64Url } from '../crypto/local-state/base64url';
import type { GeneratedAccountRecoveryKey } from '../crypto/recovery/account';

const RecoveryCardSchema = z.object({
  format: z.literal('ratchet-account-recovery-v1'),
  recovery_key_id: z.string().uuid(),
  private_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  public_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  created_at: z.string().datetime(),
});

export type RecoveryCard = z.infer<typeof RecoveryCardSchema>;

export function downloadRecoveryCard(generated: GeneratedAccountRecoveryKey): void {
  const card: RecoveryCard = {
    format: 'ratchet-account-recovery-v1',
    recovery_key_id: generated.recovery_key_id,
    private_key: bytesToBase64Url(generated.privateKey),
    public_key: bytesToBase64Url(generated.publicKey),
    created_at: new Date().toISOString(),
  };
  const blob = new Blob([JSON.stringify(card, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `ratchet-recovery-${generated.recovery_key_id}.json`;
    anchor.rel = 'noopener';
    anchor.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}

export async function readRecoveryCard(file: File): Promise<{ recovery_key_id: string; private_key: Uint8Array }> {
  const card = RecoveryCardSchema.parse(JSON.parse(await file.text()) as unknown);
  const privateKey = base64UrlToBytes(card.private_key);
  if (privateKey.length !== 32) throw new Error('Recovery card private key length is invalid');
  return { recovery_key_id: card.recovery_key_id, private_key: privateKey };
}
