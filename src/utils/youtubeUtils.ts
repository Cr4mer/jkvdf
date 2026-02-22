// Extract YouTube video ID from various YouTube URL formats
export function extractYouTubeVideoId(url: string): string | null {
  const patterns = [
    // Standard watch URLs
    /(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/)([^&\n?#]+)/,
    // Short URLs
    /youtu\.be\/([^&\n?#]+)/,
    // Embed URLs
    /youtube\.com\/embed\/([^&\n?#]+)/,
    // Mobile URLs
    /youtube\.com\/v\/([^&\n?#]+)/,
  ];

  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match && match[1]) {
      return match[1];
    }
  }

  return null;
}

// Extract timestamp from YouTube URL
export function extractYouTubeTimestamp(url: string): number {
  const timePatterns = [
    /[?&]t=(\d+)/, // ?t=123 or &t=123
    /[?&]start=(\d+)/, // ?start=123 or &start=123
  ];

  for (const pattern of timePatterns) {
    const match = url.match(pattern);
    if (match && match[1]) {
      return parseInt(match[1], 10);
    }
  }

  return 0;
}

// Generate YouTube embed URL with timestamp
export function generateYouTubeEmbedUrl(videoId: string, startSeconds: number, endSeconds?: number): string {
  let url = `https://www.youtube.com/embed/${videoId}?start=${startSeconds}&enablejsapi=1&modestbranding=1&rel=0`;
  
  if (endSeconds && endSeconds > startSeconds) {
    url += `&end=${endSeconds}`;
  }
  
  return url;
}

// Generate thumbnail URL from video ID
export function generateThumbnailUrl(videoId: string): string {
  return `https://img.youtube.com/vi/${videoId}/maxresdefault.jpg`;
}

// Generate thumbnail URL at specific timestamp
// Note: YouTube doesn't provide direct timestamp-based thumbnails
// This function returns a URL that can be used with frame extraction services
export function generateTimestampedThumbnailUrl(videoId: string, timestamp: number): string {
  // YouTube doesn't natively support timestamp-based thumbnails
  // However, we can use various services to achieve this:
  
  // Option 1: Use a screenshot service API (requires API key in production)
  // Example: `https://api.screenshotone.com/take?...`
  
  // Option 2: Use a service that extracts frames from YouTube videos
  // For now, we'll use a service that supports timestamped screenshots
  
  // Using a known service that can generate thumbnails with timestamps
  // Note: This is a placeholder - in production, you would use a real service
  // or implement your own backend API that extracts frames
  
  // The following services can be used:
  // 1. Custom backend using youtube-dl + ffmpeg
  // 2. Services like screenshotapi.io, bannerbear.com, etc.
  // 3. Self-hosted solution using Puppeteer or Playwright
  
  // For development, we'll return the default thumbnail
  // with a query parameter that indicates the timestamp
  // This can be used later to generate actual timestamped thumbnails
  return `https://img.youtube.com/vi/${videoId}/maxresdefault.jpg`;
}
