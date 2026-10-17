import type { AllowedAttachmentType } from './policy';

export const MAX_IMAGE_PREVIEW_SIDE = 4096;
export const MAX_IMAGE_PREVIEW_PIXELS = 8_000_000;
const MAX_INSPECTION_BYTES = 10 * 1024 * 1024;
const UNAVAILABLE = 'Esta imagen no admite una vista previa segura. Podés descargar el archivo.';
export type ImagePreviewPolicy = { allowed: boolean; reason: string | null; width?: number; height?: number };
type Dimensions = { width: number; height: number; animated: boolean };

/** Inspect encoded dimensions and animation before giving bytes to a decoder. */
export async function inspectImagePreview(blob: Blob, type: AllowedAttachmentType): Promise<ImagePreviewPolicy> {
  if (type === 'application/pdf') return { allowed: true, reason: null };
  if (!blob.size || blob.size > MAX_INSPECTION_BYTES) return { allowed: false, reason: UNAVAILABLE };
  const bytes = new Uint8Array(await blob.arrayBuffer());
  try {
    let size: Dimensions | undefined;
    if (type === 'image/png') size = pngSize(bytes);
    if (type === 'image/jpeg') size = jpegSize(bytes);
    if (type === 'image/gif') size = gifSize(bytes);
    if (type === 'image/webp') size = webpSize(bytes);
    if (!size || size.animated || !safeDimensions(size.width, size.height)) return { allowed: false, reason: UNAVAILABLE };
    return { allowed: true, reason: null, width: size.width, height: size.height };
  } catch {
    return { allowed: false, reason: UNAVAILABLE };
  } finally { bytes.fill(0); }
}

function safeDimensions(width: number, height: number) {
  return width > 0 && height > 0 && width <= MAX_IMAGE_PREVIEW_SIDE && height <= MAX_IMAGE_PREVIEW_SIDE && width * height <= MAX_IMAGE_PREVIEW_PIXELS;
}
function ascii(bytes: Uint8Array, start: number, length: number) { return String.fromCharCode(...bytes.subarray(start, start + length)); }
function view(bytes: Uint8Array) { return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); }

function pngSize(bytes: Uint8Array): Dimensions | undefined {
  if (bytes.length < 33 || ascii(bytes, 1, 3) !== 'PNG') return;
  const data = view(bytes);
  let size: Dimensions | undefined;
  for (let offset = 8; offset + 12 <= bytes.length;) {
    const length = data.getUint32(offset), type = ascii(bytes, offset + 4, 4);
    if (length > bytes.length - offset - 12) return;
    if (type === 'IHDR') {
      if (size || offset !== 8 || length !== 13) return;
      size = { width: data.getUint32(offset + 8), height: data.getUint32(offset + 12), animated: false };
      if (!safeDimensions(size.width, size.height)) return size;
    }
    if (type === 'acTL' || type === 'fdAT') {
      if (!size || (type === 'acTL' && length !== 8)) return;
      size.animated = true;
    }
    if (type === 'IEND') return length === 0 ? size : undefined;
    offset += length + 12;
  }
}

function jpegSize(bytes: Uint8Array): Dimensions | undefined {
  if (bytes[0] !== 0xff || bytes[1] !== 0xd8) return;
  const data = view(bytes);
  let offset = 2;
  for (let segment = 0; segment < 4096 && offset + 1 < bytes.length; segment++) {
    if (bytes[offset++] !== 0xff) return;
    while (bytes[offset] === 0xff) offset++;
    const marker = bytes[offset++]!;
    if (marker === 0xda || marker === 0xd9) return;
    if (marker === 0x01 || marker >= 0xd0 && marker <= 0xd7) continue;
    if (offset + 2 > bytes.length) return;
    const length = data.getUint16(offset);
    if (length < 2 || offset + length > bytes.length) return;
    if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
      if (length < 8) return;
      return { width: data.getUint16(offset + 5), height: data.getUint16(offset + 3), animated: false };
    }
    offset += length;
  }
}

function gifSize(bytes: Uint8Array): Dimensions | undefined {
  if (bytes.length < 14 || !['GIF87a', 'GIF89a'].includes(ascii(bytes, 0, 6))) return;
  const data = view(bytes);
  const size = { width: data.getUint16(6, true), height: data.getUint16(8, true), animated: false };
  if (!safeDimensions(size.width, size.height)) return size;
  let offset = 13 + ((bytes[10]! & 128) ? 3 * 2 ** ((bytes[10]! & 7) + 1) : 0);
  let frames = 0;
  function skipBlocks() {
    while (offset < bytes.length) {
      const length = bytes[offset++]!;
      if (!length) return true;
      offset += length;
    }
    return false;
  }
  while (offset < bytes.length) {
    const marker = bytes[offset++]!;
    if (marker === 0x3b) return frames === 1 ? size : undefined;
    if (marker === 0x21) { offset++; if (!skipBlocks()) return; continue; }
    if (marker !== 0x2c || offset + 9 > bytes.length) return;
    const left = data.getUint16(offset, true), top = data.getUint16(offset + 2, true);
    const width = data.getUint16(offset + 4, true), height = data.getUint16(offset + 6, true);
    if (!safeDimensions(width, height) || left + width > size.width || top + height > size.height) return;
    const packed = bytes[offset + 8]!;
    offset += 9 + ((packed & 128) ? 3 * 2 ** ((packed & 7) + 1) : 0);
    offset++; // LZW minimum code size.
    if (!skipBlocks()) return;
    if (++frames > 1) return { ...size, animated: true };
  }
}

function webpSize(bytes: Uint8Array): Dimensions | undefined {
  if (bytes.length < 20 || ascii(bytes, 0, 4) !== 'RIFF' || ascii(bytes, 8, 4) !== 'WEBP') return;
  const data = view(bytes), end = data.getUint32(4, true) + 8;
  if (end > bytes.length) return;
  let size: Dimensions | undefined;
  let hasImage = false;
  for (let offset = 12; offset + 8 <= end;) {
    const tag = ascii(bytes, offset, 4), length = data.getUint32(offset + 4, true), start = offset + 8;
    if (length > end - start) return;
    let current: Dimensions | undefined;
    if (tag === 'ANIM' || tag === 'ANMF') return { width: 1, height: 1, animated: true };
    if (tag === 'VP8X') {
      if (length !== 10) return;
      const u24 = (at: number) => bytes[at]! + bytes[at + 1]! * 256 + bytes[at + 2]! * 65536;
      current = { width: u24(start + 4) + 1, height: u24(start + 7) + 1, animated: Boolean(bytes[start]! & 2) };
    } else if (tag === 'VP8 ') {
      if (length < 10 || bytes[start + 3] !== 0x9d || bytes[start + 4] !== 1 || bytes[start + 5] !== 0x2a) return;
      current = { width: data.getUint16(start + 6, true) & 0x3fff, height: data.getUint16(start + 8, true) & 0x3fff, animated: false };
      hasImage = true;
    } else if (tag === 'VP8L') {
      if (length < 5 || bytes[start] !== 0x2f) return;
      current = { width: 1 + bytes[start + 1]! + ((bytes[start + 2]! & 0x3f) << 8), height: 1 + (bytes[start + 2]! >> 6) + (bytes[start + 3]! << 2) + ((bytes[start + 4]! & 0x0f) << 10), animated: false };
      hasImage = true;
    }
    if (current) {
      if (current.animated || !safeDimensions(current.width, current.height)) return current;
      if (size && (size.width !== current.width || size.height !== current.height)) return;
      size = current;
    }
    offset = start + length + (length & 1);
  }
  return hasImage ? size : undefined;
}
