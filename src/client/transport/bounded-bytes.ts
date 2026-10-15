/** Enforce the actual byte count before buffering an untrusted response. */
export async function readResponseBytes(response: Response, limit: number): Promise<Uint8Array> {
  if (!Number.isSafeInteger(limit) || limit < 0) throw new Error('Invalid response byte limit');
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > limit - length) throw new Error('Response exceeds expected byte limit');
      chunks.push(value);
      length += value.byteLength;
    }
    const result = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { result.set(chunk,offset); offset += chunk.byteLength; }
    return result;
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally { reader.releaseLock(); }
}
