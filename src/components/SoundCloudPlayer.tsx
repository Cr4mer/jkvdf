import { useRef, useState } from 'react';

const SOUNDCLOUD_URL = 'https://soundcloud.com/the-is/a-match-has-been-found';

export default function SoundCloudPlayer() {
  const [isOpen, setIsOpen] = useState(false);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  // Create the widget URL with compact size
  const widgetUrl = `https://w.soundcloud.com/player/?url=${encodeURIComponent(
    SOUNDCLOUD_URL
  )}&color=%23ff5500&auto_play=false&hide_related=false&show_comments=false&show_user=false&show_reposts=false&show_teaser=false&visual=false&sharing=false&download=false&buying=false`;

  const togglePlayer = () => {
    setIsOpen(!isOpen);
  };

  const closePlayer = (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsOpen(false);
  };

  return (
    <>
      {/* Floating Button */}
      <button
        onClick={togglePlayer}
        className={`fixed bottom-6 right-6 z-50 bg-orange-500 hover:bg-orange-600 text-white rounded-full p-3 shadow-lg transition-all duration-300 ${
          isOpen ? 'opacity-50 hover:opacity-100' : ''
        }`}
        aria-label="Toggle SoundCloud Player"
        title="Toggle SoundCloud Player"
        style={{ marginBottom: isOpen ? '90px' : '0' }}
      >
        <svg 
          className="w-5 h-5" 
          fill="currentColor" 
          viewBox="0 0 24 24"
        >
          {isOpen ? (
            <path d="M6 6h12v12H6z" />
          ) : (
            <path d="M8 5v14l11-7z" />
          )}
        </svg>
      </button>

      {/* SoundCloud Player Bottom Bar */}
      {isOpen && (
        <div className="fixed bottom-0 left-0 right-0 z-40 bg-neutral-900/95 backdrop-blur-sm border-t border-white/10 shadow-2xl">
          <div className="container mx-auto max-w-6xl px-4 py-3">
            <div className="flex items-center justify-between gap-4">
              {/* Song Title */}
              <div className="hidden sm:flex items-center gap-3 flex-shrink-0">
                <div className="text-orange-500 text-xl">🎵</div>
                <div>
                  <p className="text-white font-semibold text-sm">A Match Has Been Found</p>
                  <p className="text-gray-400 text-xs">the is</p>
                </div>
              </div>

              {/* SoundCloud Player */}
              <div className="flex-1 min-w-0">
                <iframe
                  ref={iframeRef}
                  width="100%"
                  height="80"
                  scrolling="no"
                  frameBorder="no"
                  allow="autoplay; encrypted-media"
                  src={widgetUrl}
                  className="rounded"
                />
              </div>

              {/* Close Button */}
              <button
                onClick={closePlayer}
                className="flex-shrink-0 text-gray-400 hover:text-white transition-colors"
                aria-label="Close Player"
                title="Close"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
