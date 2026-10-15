import {
  CreateOperatorAccessGrantResponseSchema,
  CreateOperatorResponseSchema,
  ListOperatorAccessGrantsResponseSchema,
  ListOperatorsResponseSchema,
  type CreateOperatorRequest,
} from '../../shared/contracts/operators';
import { apiFetch } from '../transport/api';

export async function listOperators(workspaceId: string) {
  return apiFetch(`/api/v1/operators?workspace_id=${encodeURIComponent(workspaceId)}`, {}, (value) => ListOperatorsResponseSchema.parse(value));
}

export async function createOperator(input: CreateOperatorRequest) {
  return apiFetch('/api/v1/operators', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  }, (value) => CreateOperatorResponseSchema.parse(value), { retryMode: 'none' });
}

export async function createOperatorAccessGrant(workspaceId: string, userId: string) {
  return apiFetch(`/api/v1/operators/${encodeURIComponent(userId)}/access-grants?workspace_id=${encodeURIComponent(workspaceId)}`, {
    method: 'POST',
  }, (value) => CreateOperatorAccessGrantResponseSchema.parse(value), { retryMode: 'none' });
}

export async function listOperatorAccessGrants(workspaceId: string, userId: string) {
  return apiFetch(`/api/v1/operators/${encodeURIComponent(userId)}/access-grants?workspace_id=${encodeURIComponent(workspaceId)}`, {}, (value) => ListOperatorAccessGrantsResponseSchema.parse(value));
}

export async function revokeOperatorAccessGrant(workspaceId: string, userId: string, grantId: string): Promise<void> {
  await apiFetch(`/api/v1/operators/${encodeURIComponent(userId)}/access-grants/${encodeURIComponent(grantId)}?workspace_id=${encodeURIComponent(workspaceId)}`, {
    method: 'DELETE',
  }, () => undefined, { retryMode: 'idempotent' });
}

export async function revokeOperator(workspaceId: string, userId: string): Promise<void> {
  await apiFetch(`/api/v1/operators/${encodeURIComponent(userId)}?workspace_id=${encodeURIComponent(workspaceId)}`, {
    method: 'DELETE',
  }, () => undefined, { retryMode: 'idempotent' });
}
