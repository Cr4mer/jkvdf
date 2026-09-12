import { Nade, isCheatSheet } from '@/types';
import NadeVideoPreview from './NadeVideoPreview';
import { useActiveVideo } from '@/contexts/ActiveVideoContext';
import { useMobileOptimizedImage } from '@/hooks/useMobileOptimizedImage';

type Props = {
  nade: Nade;
  onClick: (nade: Nade) => void;
  mapName?: string;
};

// Format seconds to MM:SS
function formatTimestamp(seconds: number): string {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}:${secs.toString().padStart(2, '0')}`;
}

// Format throw method for display
function formatThrowMethod(method: string): string {
  const mapping: Record<string, string> = {
    'left click throw': 'left click',
    'left + right click throw': 'left + right click',
    'jump throw': 'jump throw',
    'jumpthrow+w': 'jumpthrow+w'
  };
  return mapping[method] || method;
}

export default function NadeCard({ nade, onClick, mapName }: Props) {
  const { isMobile, getOptimizedYouTubeThumbnail } = useMobileOptimizedImage();
  const cheatSheet = isCheatSheet(nade);

  // On mobile only, use map image for inferno and overpass instead of YouTube thumbnail
  let thumbnailUrl = nade.thumbnailUrl;
  if (!thumbnailUrl) {
    // Use optimized YouTube thumbnail for mobile (hqdefault) vs desktop (maxresdefault)
    thumbnailUrl = getOptimizedYouTubeThumbnail(nade.youtubeVideoId ?? '');
  }

  if (isMobile && mapName && !cheatSheet) {
    const lowerMapName = mapName.toLowerCase();
    if (lowerMapName === 'inferno') {
      thumbnailUrl = '/inferno.jpeg';
    } else if (lowerMapName === 'overpass') {
      thumbnailUrl = '/overpass.jpg';
    }
  }

  const videoId = nade.id || `${nade.youtubeVideoId}-${nade.startSeconds}`;
  const { activeVideoId, setActiveVideoId } = useActiveVideo();
  const isPreviewActive = activeVideoId === videoId;

  const handleClick = () => {
    // Cheat sheets are a single image — open the lightbox straight away, with no
    // two-tap preview step (there's nothing to preview).
    if (cheatSheet) {
      onClick(nade);
      return;
    }
    if (isMobile) {
      // On mobile: first tap activates preview, second tap opens YouTube
      if (isPreviewActive) {
        // Second tap - open YouTube
        onClick(nade);
      } else {
        // First tap - activate preview
        setActiveVideoId(videoId);
      }
    } else {
      // On desktop: immediate click opens YouTube
      onClick(nade);
    }
  };

  return (
    <button
      onClick={handleClick}
      className="text-left group rounded-lg overflow-hidden border border-white/10 hover:border-white/20 focus:outline-none focus:ring-2 focus:ring-white/30"
    >
      <div className="aspect-video bg-neutral-900 relative">
        {cheatSheet ? (
          /* Image-only entry: show the sheet itself, no video preview. Prefer the small
             thumbnailUrl here — the full-resolution imageUrl can be multiple MB and is
             only loaded when the lightbox opens. object-contain keeps the whole sheet
             visible rather than cropping off the corners. */
          <img
            src={thumbnailUrl || nade.imageUrl}
            alt={nade.name}
            loading="lazy"
            className="absolute inset-0 w-full h-full object-contain bg-neutral-950"
          />
        ) : (
          /* Looping video preview at 2x speed */
          <NadeVideoPreview
            id={nade.id || `${nade.youtubeVideoId}-${nade.startSeconds}`}
            videoId={nade.youtubeVideoId ?? ''}
            startSeconds={nade.startSeconds}
            endSeconds={nade.endSeconds}
            className="w-full h-full"
            thumbnailUrl={thumbnailUrl}
          />
        )}

        {/* Hover overlay: magnifier for cheat sheets, play for videos */}
        <div className="absolute inset-0 bg-black/0 group-hover:bg-black/20 transition-colors flex items-center justify-center">
          <div className="opacity-0 group-hover:opacity-100 transition-opacity bg-black/60 rounded-full p-2">
            {cheatSheet ? (
              <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35M11 18a7 7 0 110-14 7 7 0 010 14zM11 8v6M8 11h6" />
              </svg>
            ) : (
              <svg className="w-8 h-8 text-white" fill="currentColor" viewBox="0 0 24 24">
                <path d="M8 5v14l11-7z"/>
              </svg>
            )}
          </div>
        </div>

        {/* Badge: "SHEET" for cheat sheets (no timestamp), otherwise the start time */}
        <div className="absolute top-2 right-2 bg-black/70 px-2 py-1 rounded text-xs font-mono text-white pointer-events-none">
          {cheatSheet ? 'SHEET' : formatTimestamp(nade.startSeconds)}
        </div>
      </div>
      <div className="p-2 text-sm opacity-90 group-hover:opacity-100">
        <div className="font-medium">{nade.name}</div>
        <div className="text-xs uppercase opacity-70">
          {nade.type === 'instant_smoke' ? 'Instant Smoke' : cheatSheet ? 'Cheat Sheet' : nade.type}
        </div>
        <div className="text-xs text-gray-400 mt-1">
          {nade.side === 'ct' ? 'CT' : nade.side === 't' ? 'T' : 'Both'}
        </div>
        {nade.tags && nade.tags.length > 0 && (
          <div className="text-xs text-amber-400/90 mt-1 flex flex-wrap gap-1">
            {nade.tags.map((tag) => (
              <span key={tag} className="bg-amber-500/20 px-1.5 py-0.5 rounded">{tag}</span>
            ))}
          </div>
        )}
        {nade.throwMethod && (() => {
          const methods = Array.isArray(nade.throwMethod) 
            ? nade.throwMethod 
            : [nade.throwMethod];
          
          // Filter out single character items (corrupted data) and keep only meaningful strings
          const validMethods = methods.filter(m => String(m).length > 1);
          
          if (validMethods.length > 0) {
            const displayMethods = validMethods.map(formatThrowMethod);
            return <div className="text-xs text-blue-400 mt-1">{displayMethods.join(' & ')}</div>;
          }
          
          return null;
        })()}
      </div>
    </button>
  );
}


