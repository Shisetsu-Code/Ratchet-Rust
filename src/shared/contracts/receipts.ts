import { z } from 'zod';

export const ReceiptStateSchema = z.enum(['DELIVERED', 'READ']);
export type ReceiptState = z.infer<typeof ReceiptStateSchema>;

export const ReceiptRequestSchema = z.object({
  message_id: z.string().uuid(),
  state: ReceiptStateSchema,
});

export const ReceiptResponseSchema = z.object({
  message_id: z.string().uuid(),
  state: ReceiptStateSchema,
  revision: z.number().int().nonnegative(),
  duplicate: z.boolean(),
});

export const ReceiptBatchRequestSchema = z.object({
  receipts: z.array(ReceiptRequestSchema).min(1).max(100),
}).superRefine((value, ctx) => {
  const seen = new Set<string>();
  for (let index = 0; index < value.receipts.length; index += 1) {
    const receipt = value.receipts[index]!;
    if (seen.has(receipt.message_id)) {
      ctx.addIssue({
        code: 'custom',
        path: ['receipts', index, 'message_id'],
        message: 'Duplicate message_id in receipt batch',
      });
    }
    seen.add(receipt.message_id);
  }
});

export const ReceiptBatchResponseSchema = z.object({
  receipts: z.array(ReceiptResponseSchema),
});
