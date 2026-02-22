import { useMobileOptimizedImage } from '@/hooks/useMobileOptimizedImage';

type Props = {
  src: string;
  alt: string;
  className?: string;
  loading?: 'lazy' | 'eager';
  width?: number;
  height?: number;
};

/**
 * Optimized image component that adds mobile-specific optimizations
 * - Adds lazy loading
 * - Optimizes YouTube thumbnails for mobile
 * - Can be extended for other optimizations
 */
export default function OptimizedImage({ 
  src, 
  alt, 
  className = '', 
  loading = 'lazy',
  width,
  height
}: Props) {
  const { optimizeImageUrl } = useMobileOptimizedImage();
  
  // Optimize the image URL for mobile if applicable
  const optimizedSrc = optimizeImageUrl(src);
  
  return (
    <img
      src={optimizedSrc}
      alt={alt}
      className={className}
      loading={loading}
      width={width}
      height={height}
    />
  );
}






