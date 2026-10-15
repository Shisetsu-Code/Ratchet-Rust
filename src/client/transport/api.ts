import { ApiProblemSchema } from '../../shared/errors/api-error';

type RetryPolicy = { attempts: number; baseMs: number };
export type RetryMode = 'default' | 'none' | 'idempotent' | 'ordered-message' | 'upload-part';
export type ApiFetchOptions = { timeoutMs?: number; retryMode?: RetryMode };

const GET_POLICY: RetryPolicy = { attempts: 3, baseMs: 500 };
const IDEMPOTENT_WRITE_POLICY: RetryPolicy = { attempts: 3, baseMs: 500 };
const ORDERED_MESSAGE_POLICY: RetryPolicy = { attempts: 6, baseMs: 250 };
const UPLOAD_PART_POLICY: RetryPolicy = { attempts: 5, baseMs: 500 };
const NO_RETRY_POLICY: RetryPolicy = { attempts: 1, baseMs: 0 };
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly type: string,
    readonly retryable: boolean,
    message: string,
    readonly expectedSenderSequence?: number,
    readonly retryAfterMs?: number,
  ) {
    super(message);
  }
}

function delay(ms: number, signal?: AbortSignal | null): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(signal.reason); return; }
    const abort = () => { clearTimeout(timer); reject(signal?.reason); };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', abort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', abort, { once: true });
  });
}

function retryAfterMs(value: string | null): number | undefined {
  if (value === null) return undefined;
  const trimmed = value.trim();
  const ms = /^\d+$/.test(trimmed) ? Number(trimmed) * 1_000 : Date.parse(trimmed) - Date.now();
  // Keep timers within their supported range; malformed headers use normal backoff.
  return Number.isFinite(ms) && ms >= 0 ? Math.min(ms, 2_147_483_647) : undefined;
}

export async function apiFetch<T>(
  path: string,
  init: RequestInit = {},
  decode: (value: unknown) => T,
  options: ApiFetchOptions = {},
): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  const retryMode = options.retryMode ?? 'default';
  const policy = retryPolicy(method, retryMode);
  const timeoutMs = options.timeoutMs ?? 10_000;
  let lastError: unknown;
  for (let attempt = 0; attempt < policy.attempts; attempt += 1) {
    if (init.signal?.aborted) throw init.signal.reason;
    const controller = new AbortController();
    const abortFromCaller = () => controller.abort(init.signal?.reason);
    init.signal?.addEventListener('abort', abortFromCaller, { once: true });
    const timer = setTimeout(() => controller.abort(new DOMException('Request timeout', 'TimeoutError')), timeoutMs);
    try {
      const response = await fetch(path, {
        ...init,
        cache: 'no-store',
        credentials: 'include',
        signal: controller.signal,
        headers: { 'X-Request-ID': crypto.randomUUID(), ...init.headers },
      });
      const body: unknown = response.status === 204 ? null : await response.json().catch(() => null);
      if (response.ok) return decode(body);
      const parsed = ApiProblemSchema.safeParse(body);
      const type = parsed.success ? parsed.data.type : 'HTTP_ERROR';
      const retryable = parsed.success ? parsed.data.retryable : RETRYABLE_STATUS.has(response.status);
      const error = new ApiError(
        response.status,
        type,
        retryable,
        parsed.success ? parsed.data.title : `HTTP ${response.status}`,
        parsed.success ? parsed.data.expected_sender_sequence : undefined,
        retryAfterMs(response.headers.get('Retry-After')),
      );
      if (!retryable || attempt === policy.attempts - 1) throw error;
      lastError = error;
    } catch (error) {
      lastError = error;
      if (init.signal?.aborted) throw init.signal.reason;
      if (error instanceof ApiError && !error.retryable) throw error;
      if (attempt === policy.attempts - 1) throw error;
    } finally {
      clearTimeout(timer);
      init.signal?.removeEventListener('abort', abortFromCaller);
    }

    // A later ordered message may legitimately reach D1 a few milliseconds
    // before its predecessor. Retry that specific condition aggressively;
    // ordinary network/5xx failures retain normal exponential backoff.
    const cap = retryMode === 'ordered-message'
      && lastError instanceof ApiError
      && lastError.type === 'SENDER_SEQUENCE_GAP'
      ? 20 * (attempt + 1)
      : policy.baseMs * 2 ** attempt;
    const serverWait = lastError instanceof ApiError ? lastError.retryAfterMs ?? 0 : 0;
    await delay(Math.max(serverWait, Math.floor(Math.random() * Math.max(1, cap))), init.signal);
  }
  throw lastError instanceof Error ? lastError : new Error('Request failed');
}

function retryPolicy(method: string, mode: RetryMode): RetryPolicy {
  if (mode === 'none') return NO_RETRY_POLICY;
  if (mode === 'idempotent') return IDEMPOTENT_WRITE_POLICY;
  if (mode === 'ordered-message') return ORDERED_MESSAGE_POLICY;
  if (mode === 'upload-part') return UPLOAD_PART_POLICY;
  return method === 'GET' || method === 'HEAD' ? GET_POLICY : NO_RETRY_POLICY;
}
