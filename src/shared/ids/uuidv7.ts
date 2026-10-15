let lastTimestampMs = -1;
let sequence = 0;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * RFC 9562 UUIDv7 with process-local monotonic ordering.
 *
 * The previous generator filled rand_a entirely with randomness. Two UI events
 * created in the same millisecond therefore had UUIDs whose lexical order was
 * random, which mattered because optimistic messages use client_message_id as
 * their final tie-breaker before an authoritative D1 revision exists.
 *
 * We use the 12-bit rand_a field as a monotonic per-millisecond sequence and
 * keep 62 random bits in rand_b. If more than 4096 IDs are requested in one
 * millisecond (or the wall clock moves backwards), logical time advances rather
 * than emitting an ID that sorts before one already issued in this process.
 */
export function uuidv7(now = Date.now()): string {
  const requestedMs = Math.max(0, Math.floor(now));
  let ms = requestedMs;

  if (ms > lastTimestampMs) {
    lastTimestampMs = ms;
    sequence = 0;
  } else {
    ms = lastTimestampMs;
    sequence += 1;
    if (sequence > 0x0fff) {
      lastTimestampMs += 1;
      ms = lastTimestampMs;
      sequence = 0;
    }
  }

  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let timestamp = BigInt(ms);
  for (let i = 5; i >= 0; i -= 1) {
    bytes[i] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }

  // version=7 + 12-bit monotonic rand_a
  bytes[6] = 0x70 | ((sequence >>> 8) & 0x0f);
  bytes[7] = sequence & 0xff;
  // RFC variant 10xx while preserving 62 random rand_b bits.
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;

  const h = hex(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
