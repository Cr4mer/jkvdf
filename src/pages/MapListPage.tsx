import { collection } from 'firebase/firestore';
import { db } from '@/firebase';
import MapCard from '@/components/MapCard';
import { Cs2Map } from '@/types';
import { useFirestoreCollection } from '@/hooks/useFirestoreCollection';

export default function MapListPage() {
  const mapsRef = collection(db, 'maps');
  const { data: maps, loading, error } = useFirestoreCollection<Cs2Map>(mapsRef);

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-4">Maps</h1>
      {loading && <div>Loading maps…</div>}
      {error && (
        <div className="text-red-400">
          Failed to load maps: {error.message}
          <br />
          <small className="text-xs opacity-70">
            Check console for details. Make sure Firestore rules are deployed.
          </small>
        </div>
      )}
      {maps && (
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4">
          {maps.map((m) => (
            <MapCard key={m.id} map={m} />
          ))}
        </div>
      )}
    </div>
  );
}

