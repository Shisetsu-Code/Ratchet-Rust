import { useEffect, useState } from 'react';
import { parseChatWallpaper, type ChatWallpaper } from './wallpaper';

export function createWallpaperObjectUrl(wallpaper: ChatWallpaper): string | null {
  const safe = parseChatWallpaper(wallpaper);
  if (safe.kind !== 'custom') return null;
  const separator = safe.dataUrl.indexOf(',');
  const mime = safe.dataUrl.slice(5, safe.dataUrl.indexOf(';'));
  const bytes = Uint8Array.from(atob(safe.dataUrl.slice(separator + 1)), character => character.charCodeAt(0));
  return URL.createObjectURL(new Blob([bytes], { type: mime }));
}

/** Keep large data URLs out of CSS; release each image when replaced/unmounted. */
export function useWallpaperObjectUrl(wallpaper: ChatWallpaper): string | null {
  const dataUrl = wallpaper.kind === 'custom' ? wallpaper.dataUrl : null;
  const [image, setImage] = useState<{ source: string; url: string } | null>(null);
  useEffect(() => {
    if (!dataUrl) { setImage(null); return; }
    const url = createWallpaperObjectUrl({ kind: 'custom', dataUrl });
    if (!url) { setImage(null); return; }
    setImage({ source: dataUrl, url });
    return () => URL.revokeObjectURL(url);
  }, [dataUrl]);
  return image?.source === dataUrl ? image.url : null;
}
