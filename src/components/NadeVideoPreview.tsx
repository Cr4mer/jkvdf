import { useEffect, useState, useRef } from 'react';
import { useActiveVideo } from '@/contexts/ActiveVideoContext';
import { useMobileOptimizedImage } from '@/hooks/useMobileOptimizedImage';

type Props = {
  videoId: string;
  startSeconds: number;
  endSeconds?: number;
  className?: string;
  thumbnailUrl?: string;
  id: string; // Unique identifier for this video preview
};

export default function NadeVideoPreview({ 
  videoId, 
  startSeconds, 
  endSeconds, 
  className = "w-full h-full",
  thumbnailUrl,
  id
}: Props) {
  const [isInView, setIsInView] = useState(false);
  const [shouldLoadVideo, setShouldLoadVideo] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const timeoutRef = useRef<number | null>(null);
  const touchStartRef = useRef<{ x: number; y: number; time: number } | null>(null);
  const videoEndTime = endSeconds || (startSeconds + 5);
  const videoDuration = videoEndTime - startSeconds;
  
  const { activeVideoId, setActiveVideoId } = useActiveVideo();
  const isActive = activeVideoId === id;
  
  const { isMobile, getOptimizedYouTubeThumbnail } = useMobileOptimizedImage();
  
  // Fallback thumbnail URL - use optimized version for mobile
  const fallbackThumbnail = thumbnailUrl || getOptimizedYouTubeThumbnail(videoId);
  
  // Force load when active on mobile (for immediate preview on tap)
  useEffect(() => {
    if (isMobile && isActive) {
      setShouldLoadVideo(true);
    }
  }, [isMobile, isActive]);

  // Intersection Observer for lazy loading
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setIsInView(true);
            // On mobile, delay loading to prevent overload (unless active)
            if (isMobile) {
              // If already active, load immediately
              if (isActive) {
                setShouldLoadVideo(true);
              } else {
                // Clear any pending timeout
                if (timeoutRef.current) clearTimeout(timeoutRef.current);
                // Only load after a short delay, and only if still in view
                timeoutRef.current = setTimeout(() => {
                  if (containerRef.current) {
                    setShouldLoadVideo(true);
                  }
                }, 300);
              }
            } else {
              setShouldLoadVideo(true);
            }
          } else {
            // Clear timeout if element goes out of view before video loads
            if (timeoutRef.current) {
              clearTimeout(timeoutRef.current);
              timeoutRef.current = null;
            }
            // Unload video when out of view to save resources (optional for better mobile performance)
            // But keep it loaded if active
            if (isMobile && !isActive) {
              setShouldLoadVideo(false);
            }
          }
        });
      },
      {
        rootMargin: '50px', // Start loading 50px before entering viewport
        threshold: 0.01
      }
    );

    const currentRef = containerRef.current;
    if (currentRef) {
      observer.observe(currentRef);
    }

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
      if (currentRef) {
        observer.unobserve(currentRef);
      }
    };
  }, [isMobile, isActive]);

  // Generate the YouTube video URL for the segment (only when should load)
  const videoUrl = shouldLoadVideo || isActive
    ? `https://www.youtube.com/embed/${videoId}?start=${startSeconds}&end=${videoEndTime}&autoplay=${isActive && !isMobile ? 1 : 0}&mute=1&playsinline=1&loop=1&playlist=${videoId}&controls=0&modestbranding=1&rel=0&enablejsapi=1&iv_load_policy=3&origin=${encodeURIComponent(window.location.origin)}`
    : null;

  // Helper to talk to YouTube iframe player
  const postToPlayer = (func: string, args: unknown[] = []) => {
    const iframe = iframeRef.current;
    if (!iframe) return;
    try {
      iframe.contentWindow?.postMessage(
        JSON.stringify({ event: 'command', func, args }),
        '*'
      );
    } catch {}
  };

  // Control video playback based on active state
  useEffect(() => {
    if (!iframeRef.current) return;

    if (isMobile) {
      // On mobile, only play when active (video will load if isActive is true, even if shouldLoadVideo is false)
      if (isActive) {
        postToPlayer('mute');
        postToPlayer('seekTo', [startSeconds, true]);
        postToPlayer('playVideo');
        postToPlayer('setPlaybackRate', [2.0]);
      } else {
        postToPlayer('pauseVideo');
      }
    } else {
      // On desktop, auto-play when loaded and in view
      if (shouldLoadVideo) {
        postToPlayer('mute');
        postToPlayer('seekTo', [startSeconds, true]);
        postToPlayer('playVideo');
        postToPlayer('setPlaybackRate', [2.0]);
        // When active, ensure it's playing (in case it was paused)
        if (isActive) {
          postToPlayer('playVideo');
        }
      }
    }
  }, [isActive, shouldLoadVideo, isMobile, startSeconds]);

  // Refresh the iframe every (duration / 2) seconds at 2x speed to keep it looping correctly (desktop only, when loaded)
  useEffect(() => {
    if (!shouldLoadVideo || isMobile || !videoUrl) return;
    
    const refreshInterval = (videoDuration / 2) * 1000;
    const intervalId = setInterval(() => {
      // Force reload by updating iframe src with timestamp
      if (containerRef.current) {
        const iframe = containerRef.current.querySelector('iframe');
        if (iframe) {
          const url = new URL(iframe.src);
          url.searchParams.set('t', Date.now().toString());
          iframe.src = url.toString();
        }
      }
    }, refreshInterval);
    
    return () => clearInterval(intervalId);
  }, [shouldLoadVideo, isMobile, videoDuration, videoUrl]);

  // Detect scroll/touch gestures to activate video
  const handleTouchStart = (e: React.TouchEvent) => {
    const touch = e.touches[0];
    touchStartRef.current = {
      x: touch.clientX,
      y: touch.clientY,
      time: Date.now()
    };
    // On mobile, let NadeCard handle the tap behavior (don't activate here)
    // On desktop, activate immediately on touch for better responsiveness
    if (!isMobile && activeVideoId !== id) {
      setActiveVideoId(id);
    }
  };

  const handleTouchMove = (e: React.TouchEvent) => {
    if (!touchStartRef.current) return;
    
    const touch = e.touches[0];
    const deltaX = Math.abs(touch.clientX - touchStartRef.current.x);
    const deltaY = Math.abs(touch.clientY - touchStartRef.current.y);
    const deltaTime = Date.now() - touchStartRef.current.time;
    
    // If there's significant movement (scroll gesture), activate this video (desktop only)
    // On mobile, let NadeCard handle the tap behavior
    if (!isMobile && (deltaX > 3 || deltaY > 3) && deltaTime < 1000) {
      if (activeVideoId !== id) {
        setActiveVideoId(id);
      }
    }
  };

  const handleTouchEnd = () => {
    touchStartRef.current = null;
  };

  // Also handle mouse events for desktop (scroll while hovering)
  const handleWheel = (e: React.WheelEvent) => {
    // If scrolling on this video, activate it
    if (activeVideoId !== id) {
      setActiveVideoId(id);
    }
  };

  const handleMouseEnter = () => {
    // On desktop, activate on hover (optional - you can remove this if you only want scroll activation)
    // setActiveVideoId(id);
  };

  return (
    <div
      ref={containerRef}
      className={`relative ${className}`}
      onTouchStart={handleTouchStart}
      onTouchMove={handleTouchMove}
      onTouchEnd={handleTouchEnd}
      onWheel={handleWheel}
      onMouseEnter={handleMouseEnter}
      style={{ touchAction: 'auto' }}
    >
      {/* Thumbnail - shown when video is not visible */}
      <img 
        src={fallbackThumbnail} 
        alt="Video preview" 
        className="absolute inset-0 w-full h-full object-cover"
        style={{ 
          opacity: (isMobile ? (isActive ? 0 : 1) : (shouldLoadVideo ? 0 : 1)),
          transition: 'opacity 0.3s'
        }}
      />
      
      {/* Looping video preview - only loaded when in view, shouldLoadVideo is true, or when active */}
      {(shouldLoadVideo || isActive) && videoUrl && (
        <iframe
          src={videoUrl}
          className="absolute inset-0 w-full h-full"
          allow="autoplay; encrypted-media; picture-in-picture; fullscreen"
          allowFullScreen
          loading="lazy"
          style={{ 
            pointerEvents: 'none',
            opacity: (isMobile ? (isActive ? 1 : 0) : (shouldLoadVideo ? 1 : 0)), // Mobile: fully visible when active, Desktop: when loaded and in view
            transition: 'opacity 0.3s'
          }}
          ref={iframeRef}
          onLoad={(e) => {
            // Auto-play on desktop when loaded, or on mobile when active
            if ((!isMobile && shouldLoadVideo) || (isMobile && isActive)) {
              const iframe = e.currentTarget;
              try {
                // Ensure muted for autoplay policies
                // @ts-ignore - accessing YouTube API
                iframe.contentWindow.postMessage('{"event":"command","func":"mute","args":[]}', '*');
                // @ts-ignore - accessing YouTube API
                iframe.contentWindow.postMessage('{"event":"command","func":"setPlaybackRate","args":[2.0]}', '*');
                // @ts-ignore - accessing YouTube API
                iframe.contentWindow.postMessage('{"event":"command","func":"playVideo","args":[]}', '*');
              } catch (err) {
                console.log('Could not set playback rate');
              }
            }
          }}
        />
      )}
    </div>
  );
}
