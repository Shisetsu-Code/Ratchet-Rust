import { z } from 'zod';

const SenderSequenceStateSchema = z.object({
  version: z.literal(1),
  last_allocated: z.number().int().nonnegative(),
});

export type SenderSequenceState = z.infer<typeof SenderSequenceStateSchema>;

export function senderSequenceSettingKey(chatId: string, senderDeviceId: string): string {
  return `sender-sequence:v1:${chatId}:${senderDeviceId}`;
}

export function parseSenderSequenceState(value: unknown): SenderSequenceState | null {
  const parsed = SenderSequenceStateSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}
