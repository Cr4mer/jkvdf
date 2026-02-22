import { useMemo } from 'react';

/**
 * Hook to optimize image URLs for mobile devices
 * Returns a lower quality but still good quality version for mobile to improve loading times
 */
export function useMobileOptimizedImage() {
  const isMobile = useMemo(() => {
    if (typeof window === 'undefined') return false;
    return /iPhone|iPad|iPod|Android/i.test(navigator.userAgent) || window.innerWidth < 768;
  }, []);

  /**
   * Optimizes YouTube thumbnail URLs for mobile
   * Mobile: hqdefault.jpg (480x360) - good quality, smaller file
   * Desktop: maxresdefault.jpg (1280x720) - maximum quality
   */
  const getOptimizedYouTubeThumbnail = (videoId: string, useMaxRes: boolean = false): string => {
    if (useMaxRes || !isMobile) {
      return `https://img.youtube.com/vi/${videoId}/maxresdefault.jpg`;
    }
    // Use hqdefault which is 480x360 - still good quality but much smaller file size
    return `https://img.youtube.com/vi/${videoId}/hqdefault.jpg`;
  };

  /**
   * Optimizes any image URL with query parameters for compression/quality
   * Can be used with CDNs that support quality parameters
   */
  const optimizeImageUrl = (url: string, quality: number = 80): string => {
    if (!isMobile) return url;
    
    // If it's a YouTube thumbnail, use the optimized function
    if (url.includes('youtube.com') || url.includes('ytimg.com')) {
      const videoIdMatch = url.match(/\/vi\/([^\/]+)/);
      if (videoIdMatch) {
        return getOptimizedYouTubeThumbnail(videoIdMatch[1]);
      }
    }
    
    // For other URLs, add quality parameter if supported
    const urlObj = new URL(url, window.location.origin);
    if (!urlObj.searchParams.has('q')) {
      urlObj.searchParams.set('q', quality.toString());
    }
    return urlObj.toString();
  };

  return {
    isMobile,
    getOptimizedYouTubeThumbnail,
    optimizeImageUrl,
  };
}









