import { detectAllowedAttachmentType, MAX_WALLPAPER_BYTES, validateWallpaperFile } from '../attachments/policy';

const MAX_SOURCE_BYTES = 20 * 1024 * 1024;
const MAX_SIDE = 1600;

/** Keep small originals; reduce phone exports locally before encryption/upload. */
export async function prepareWallpaperImage(file: File): Promise<File> {
  if (file.size <= MAX_WALLPAPER_BYTES) {
    await validateWallpaperFile(file);
    return file;
  }
  if (file.size > MAX_SOURCE_BYTES) {
    throw new Error(`El teléfono entregó una imagen de ${(file.size / 1024 / 1024).toFixed(1)} MB. Elegí una copia de hasta 20 MB para reducirla.`);
  }
  const detected = await detectAllowedAttachmentType(file);
  if (!detected || detected === 'application/pdf') throw new Error('El fondo debe ser una imagen JPG, PNG, WebP o GIF.');
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file, { resizeWidth: MAX_SIDE, resizeQuality: 'high', imageOrientation: 'from-image' });
  } catch {
    throw new Error('No se pudo leer esta imagen. Guardá una copia como JPG o PNG y volvé a elegirla.');
  }
  const canvas = document.createElement('canvas');
  try {
    const scale = Math.min(1, MAX_SIDE / bitmap.width, MAX_SIDE / bitmap.height);
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const context = canvas.getContext('2d');
    if (!context) throw new Error('Este navegador no pudo preparar la imagen.');
    context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    for (const quality of [0.85, 0.65, 0.45]) {
      const blob = await new Promise<Blob | null>(resolve => canvas.toBlob(resolve, 'image/webp', quality));
      if (blob && blob.size > 0 && blob.size <= MAX_WALLPAPER_BYTES) {
        const prepared = new File([blob], 'fondo', { type: blob.type });
        await validateWallpaperFile(prepared);
        return prepared;
      }
    }
    throw new Error('No se pudo reducir la imagen a 3 MB. Elegí una versión de menor resolución.');
  } finally {
    bitmap.close();
    canvas.width = 0;
    canvas.height = 0;
  }
}
