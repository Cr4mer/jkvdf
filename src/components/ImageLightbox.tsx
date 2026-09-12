import { useState } from 'react';
import { Nade } from '@/types';

type Props = {
  nade: Nade;
  onClose: () => void;
};

/**
 * Full-resolution viewer for image-only entries (cheat sheets).
 *
 * Cheat sheets carry fine detail (crosshair marks, numbered boxes), so pixels matter:
 * "Fit" scales the whole sheet to the viewport, "Actual size" shows it 1:1 with
 * scrolling, and "Open original" hands off to the browser's own viewer for zooming.
 */
export default function ImageLightbox({ nade, onClose }: Props) {
  const [actualSize, setActualSize] = useState(false);
  const src = nade.imageUrl || nade.thumbnailUrl;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={nade.name}
      className="fixed inset-0 z-50 bg-black/85 p-3 sm:p-6 flex flex-col"
      onClick={onClose}
    >
      <div className="flex items-center justify-between gap-3 mb-3 flex-shrink-0" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-sm sm:text-base font-semibold truncate">{nade.name}</h2>
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            type="button"
            onClick={() => setActualSize((v) => !v)}
            className="px-3 py-1.5 rounded-md bg-white/10 hover:bg-white/20 text-xs sm:text-sm font-medium transition-colors"
          >
            {actualSize ? 'Fit to screen' : 'Actual size'}
          </button>
          <a
            href={src}
            target="_blank"
            rel="noopener noreferrer"
            className="px-3 py-1.5 rounded-md bg-white/10 hover:bg-white/20 text-xs sm:text-sm font-medium transition-colors"
          >
            Open original
          </a>
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-md bg-white text-black text-xs sm:text-sm font-medium"
          >
            Close
          </button>
        </div>
      </div>

      <div
        className={`flex-1 min-h-0 rounded-lg ${actualSize ? 'overflow-auto' : 'overflow-hidden flex items-center justify-center'}`}
        onClick={(e) => e.stopPropagation()}
      >
        <img
          src={src}
          alt={nade.name}
          className={actualSize ? 'max-w-none' : 'max-w-full max-h-full object-contain'}
        />
      </div>
    </div>
  );
}
