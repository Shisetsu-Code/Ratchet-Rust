import {
  CreateInvitationResponseSchema,
  ClaimReferralResponseSchema,
  type CreateInvitationRequestSchema,
} from '../../shared/contracts/invitations';
import type { z } from 'zod';
import { apiFetch } from '../transport/api';

type CreateInvitationRequest = z.infer<typeof CreateInvitationRequestSchema>;

export async function createInvitation(input: CreateInvitationRequest) {
  return apiFetch('/api/v1/invitations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  }, (value) => CreateInvitationResponseSchema.parse(value), { retryMode: 'none' });
}

export async function claimReferral(token: string) {
  return apiFetch(`/api/v1/invitations/${encodeURIComponent(token)}/claim`, {
    method: 'POST',
  }, (value) => ClaimReferralResponseSchema.parse(value), { retryMode: 'none' });
}
