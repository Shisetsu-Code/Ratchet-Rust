import { MAX_ATTACHMENT_PLAINTEXT_BYTES } from '../../shared/contracts/attachments';
import { MAX_WALLPAPER_PLAINTEXT_BYTES } from '../../shared/contracts/wallpaper';

export const ALLOWED_ATTACHMENT_ACCEPT = '.jpg,.jpeg,.png,.webp,.gif,.pdf,image/jpeg,image/png,image/webp,image/gif,application/pdf';
export const MAX_WALLPAPER_BYTES = MAX_WALLPAPER_PLAINTEXT_BYTES;

export type AllowedAttachmentType = 'image/jpeg' | 'image/png' | 'image/webp' | 'image/gif' | 'application/pdf';
export type AllowedImageType = Exclude<AllowedAttachmentType, 'application/pdf'>;

const EXTENSION_BY_TYPE: Record<AllowedAttachmentType, string> = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
  'image/gif': '.gif',
  'application/pdf': '.pdf',
};

export async function validateAttachmentFile(file: File): Promise<AllowedAttachmentType> {
  if (file.size === 0) throw new Error('El archivo está vacío.');
  if (file.size > MAX_ATTACHMENT_PLAINTEXT_BYTES) throw new Error('El archivo supera el límite de 10 MB.');
  const detected = await detectAllowedAttachmentType(file);
  if (!detected) throw new Error('Sólo se permiten fotos JPG, PNG, WebP o GIF y documentos PDF.');
  return detected;
}

export async function validateWallpaperFile(file: File): Promise<AllowedImageType> {
  if (file.size === 0) throw new Error('La imagen está vacía.');
  if (file.size > MAX_WALLPAPER_BYTES) throw new Error('La imagen de fondo no puede superar 3 MB.');
  const detected = await detectAllowedAttachmentType(file);
  if (!detected || detected === 'application/pdf') throw new Error('El fondo debe ser una imagen JPG, PNG, WebP o GIF.');
  return detected;
}

export async function detectAllowedAttachmentType(file: Blob): Promise<AllowedAttachmentType | null> {
  const bytes = new Uint8Array(await file.slice(0, 16).arrayBuffer());
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'image/png';
  if (ascii(bytes, 0, 6) === 'GIF87a' || ascii(bytes, 0, 6) === 'GIF89a') return 'image/gif';
  if (ascii(bytes, 0, 4) === 'RIFF' && ascii(bytes, 8, 4) === 'WEBP') return 'image/webp';
  if (ascii(bytes, 0, 5) === '%PDF-') return 'application/pdf';
  return null;
}

export function safeAttachmentName(name: string, type: AllowedAttachmentType): string {
  const cleaned = [...name.normalize('NFC')]
    .filter(isSafeFilenameCharacter)
    .join('')
    .replace(/[\\/]/g, '')
    .replace(/^[. ]+/g, '')
    .replace(/[. ]+$/g, '')
    .trim()
    .slice(0, 180);
  const extension = EXTENSION_BY_TYPE[type];
  const stem = (cleaned || 'adjunto').replace(/\.[^.]{1,10}$/u, '').slice(0, 180 - extension.length) || 'adjunto';
  return `${stem}${extension}`;
}

function isSafeFilenameCharacter(character: string): boolean {
  const codePoint = character.codePointAt(0) ?? 0;
  return !(
    codePoint <= 0x1f
    || (codePoint >= 0x7f && codePoint <= 0x9f)
    || codePoint === 0x061c
    || codePoint === 0x200e || codePoint === 0x200f
    || (codePoint >= 0x202a && codePoint <= 0x202e)
    || (codePoint >= 0x2066 && codePoint <= 0x2069)
  );
}

function startsWith(value: Uint8Array, expected: number[]): boolean {
  return expected.every((byte, index) => value[index] === byte);
}

function ascii(value: Uint8Array, offset: number, length: number): string {
  if (value.length < offset + length) return '';
  return String.fromCharCode(...value.subarray(offset, offset + length));
}
