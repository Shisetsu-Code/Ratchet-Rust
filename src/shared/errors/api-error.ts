import { z } from 'zod';

export const ApiProblemSchema = z.object({
  type: z.string().min(1),
  title: z.string().min(1),
  status: z.number().int().min(400).max(599),
  request_id: z.string().min(1),
  retryable: z.boolean(),
  expected_sender_sequence: z.number().int().positive().optional(),
});
export type ApiProblem = z.infer<typeof ApiProblemSchema>;

export function problem(
  type: string,
  title: string,
  status: number,
  requestId: string,
  retryable = false,
  expectedSenderSequence?: number,
): ApiProblem {
  return {
    type,
    title,
    status,
    request_id: requestId,
    retryable,
    ...(expectedSenderSequence !== undefined ? { expected_sender_sequence: expectedSenderSequence } : {}),
  };
}
