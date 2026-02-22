import { Nade } from '@/types';

type Props = {
  nade: Nade;
  onClose: () => void;
};

export default function YouTubePlayer({ nade, onClose }: Props) {
  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4"
      onClick={onClose}
    >
      <div className="w-full max-w-4xl" onClick={(e) => e.stopPropagation()}>
        <div className="aspect-video bg-black rounded-lg overflow-hidden">
          <iframe
            title={nade.name}
            className="w-full h-full"
            src={`https://www.youtube.com/embed/${nade.youtubeVideoId}?start=${nade.startSeconds}&${nade.endSeconds ? `end=${nade.endSeconds}&` : ''}enablejsapi=1&modestbranding=1&rel=0&playsinline=1&origin=${encodeURIComponent(window.location.origin)}`}
            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share; fullscreen"
            allowFullScreen
          />
        </div>
        <div className="flex justify-end mt-3">
          <button onClick={onClose} className="px-3 py-1.5 rounded-md bg-white text-black text-sm">Close</button>
        </div>
      </div>
    </div>
  );
}


