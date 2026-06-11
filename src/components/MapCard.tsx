import { Link } from 'react-router-dom';
import { Cs2Map } from '@/types';
import { versionedAsset } from '@/utils/assets';

export default function MapCard({ map }: { map: Cs2Map }) {
  return (
    <Link to={`/map/${map.id}`} className="group rounded-lg overflow-hidden border border-white/10 hover:border-white/20 focus:outline-none focus:ring-2 focus:ring-white/30">
      <div className="aspect-video bg-neutral-900">
        <img src={versionedAsset(map.thumbnailUrl)} alt={map.name} className="w-full h-full object-cover" />
      </div>
      <div className="p-2 text-sm opacity-90 group-hover:opacity-100">{map.name}</div>
    </Link>
  );
}


