import { useParams } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { collection, doc, getDoc } from 'firebase/firestore';
import { db } from '@/firebase';
import { Nade, Cs2Map } from '@/types';
import { useFirestoreCollection } from '@/hooks/useFirestoreCollection';
import NadeCard from '@/components/NadeCard';
import YouTubePlayer from '@/components/YouTubePlayer';

export default function NadeGalleryPage() {
  const { mapId } = useParams();
  const [active, setActive] = useState<Nade | null>(null);
  const [selectedTypes, setSelectedTypes] = useState<Set<string>>(new Set(['all']));
  const [selectedSides, setSelectedSides] = useState<Set<string>>(new Set(['ct', 't']));
  const [mapName, setMapName] = useState<string | null>(null);

  const nadesRef = collection(db, `maps/${mapId}/nades`);
  const { data: nades, loading, error } = useFirestoreCollection<Nade>(nadesRef);

  // Fetch map name to determine thumbnail
  useEffect(() => {
    if (mapId) {
      getDoc(doc(db, 'maps', mapId)).then((docSnap) => {
        if (docSnap.exists()) {
          const mapData = docSnap.data() as Cs2Map;
          setMapName(mapData.name);
        }
      });
    }
  }, [mapId]);

  // Nade type options with images
  const nadeTypes = [
    { value: 'all', label: 'All Types', image: null, noIcon: true },
    { value: 'smoke', label: 'Smoke', image: '/smoke.png' },
    { value: 'instant_smoke', label: 'Instant Smoke', image: '/smoke.png' },
    { value: 'flash', label: 'Flash', image: '/flash.png' },
    { value: 'molotov', label: 'Molotov', image: '/molo.png' },
    { value: 'he', label: 'HE Grenade', image: '/HE.png' },
    { value: 'sæt', label: 'Sæt', image: null, noIcon: false },
  ];

  // Side options
  const sideOptions = [
    { value: 'ct', label: 'CT', image: '/CT.png' },
    { value: 't', label: 'T', image: '/T.png' },
  ];

  const toggleType = (type: string) => {
    const newSelected = new Set(selectedTypes);
    
    if (type === 'all') {
      // If selecting "all", clear other selections
      newSelected.clear();
      newSelected.add('all');
    } else {
      // Remove "all" if it's selected
      newSelected.delete('all');
      
      if (newSelected.has(type)) {
        newSelected.delete(type);
        // If no types selected, select "all"
        if (newSelected.size === 0) {
          newSelected.add('all');
        }
      } else {
        newSelected.add(type);
      }
    }
    
    setSelectedTypes(newSelected);
  };

  const toggleSide = (side: string) => {
    const newSelected = new Set(selectedSides);
    
    if (newSelected.has(side)) {
      newSelected.delete(side);
    } else {
      newSelected.add(side);
    }
    
    setSelectedSides(newSelected);
  };

  // Filter nades based on selected types and sides
  const filteredNades = nades?.filter(nade => {
    const typeMatch = selectedTypes.has('all') || selectedTypes.has(nade.type);
    const sideMatch = selectedSides.has(nade.side || 'ct');
    return typeMatch && sideMatch;
  }) || [];

  // If "sæt" is selected, sort by startSeconds to show them in order
  const displayNades = selectedTypes.has('sæt') && selectedTypes.size === 1
    ? [...filteredNades].sort((a, b) => (a.startSeconds || 0) - (b.startSeconds || 0))
    : filteredNades;

  return (
    <div className="flex flex-col lg:flex-row gap-6 mt-12 sm:mt-60 px-4 lg:px-0">
      {/* Filter Sidebar - Hidden on mobile, shown on desktop */}
      <div className="hidden lg:block w-48 flex-shrink-0 bg-neutral-900/50 backdrop-blur-sm p-4 rounded-lg border border-white/10">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Filter by Type</h2>
        <div className="space-y-2">
          {nadeTypes.map((type) => (
            <label
              key={type.value}
              className={`flex items-center gap-3 p-3 rounded-md cursor-pointer transition-colors ${
                selectedTypes.has(type.value)
                  ? 'bg-neutral-800 border border-neutral-700'
                  : 'hover:bg-neutral-800/50'
              }`}
              title={type.label}
            >
              <input
                type="checkbox"
                checked={selectedTypes.has(type.value)}
                onChange={() => toggleType(type.value)}
                className="w-4 h-4 accent-blue-600"
              />
              {type.value === 'all' && (
                <span className="text-sm font-semibold">ALL</span>
              )}
              {type.value === 'sæt' && (
                <div className="flex gap-1">
                  <img src="/smoke.png" alt="Smoke" className="w-10 h-10 object-contain" />
                  <img src="/flash.png" alt="Flash" className="w-10 h-10 object-contain" />
                  <img src="/molo.png" alt="Molotov" className="w-10 h-10 object-contain" />
                </div>
              )}
              {type.value !== 'sæt' && type.value !== 'all' && type.image && (
                <img src={type.image} alt={type.label} className="w-16 h-16 object-contain" />
              )}
              {type.value !== 'sæt' && type.value !== 'all' && !type.image && !type.noIcon && (
                <span className="text-3xl">🎬</span>
              )}
            </label>
          ))}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1">
        <h1 className="text-xl lg:text-2xl font-semibold capitalize mb-4 bg-neutral-900/50 backdrop-blur-sm p-4 rounded-lg border border-white/10">{mapId} Nades</h1>

        {/* Mobile Filters - Top of page on mobile */}
        <div className="lg:hidden mb-6 space-y-4">
          {/* Type Filter */}
          <div className="bg-neutral-900/50 backdrop-blur-sm p-4 rounded-lg border border-white/10">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Filter by Type</h2>
            <div className="grid grid-cols-3 gap-2">
              {nadeTypes.map((type) => (
                <label
                  key={type.value}
                  className={`flex flex-col items-center justify-center gap-2 p-2 rounded-md cursor-pointer transition-colors ${
                    selectedTypes.has(type.value)
                      ? 'bg-neutral-800 border border-neutral-700'
                      : 'hover:bg-neutral-800/50'
                  }`}
                  title={type.label}
                >
                  <input
                    type="checkbox"
                    checked={selectedTypes.has(type.value)}
                    onChange={() => toggleType(type.value)}
                    className="w-4 h-4 accent-blue-600"
                  />
                  {type.value === 'all' && (
                    <span className="text-xs font-semibold text-center">ALL</span>
                  )}
                  {type.value === 'sæt' && (
                    <div className="flex gap-1">
                      <img src="/smoke.png" alt="Smoke" className="w-6 h-6 object-contain" />
                      <img src="/flash.png" alt="Flash" className="w-6 h-6 object-contain" />
                      <img src="/molo.png" alt="Molotov" className="w-6 h-6 object-contain" />
                    </div>
                  )}
                  {type.value !== 'sæt' && type.value !== 'all' && type.image && (
                    <img src={type.image} alt={type.label} className="w-10 h-10 object-contain" />
                  )}
                  {type.value !== 'sæt' && type.value !== 'all' && !type.image && !type.noIcon && (
                    <span className="text-2xl">🎬</span>
                  )}
                  {type.value !== 'all' && type.value !== 'sæt' && (
                    <span className="text-xs text-center">{type.label}</span>
                  )}
                </label>
              ))}
            </div>
          </div>

          {/* Side Filter */}
          <div className="bg-neutral-900/50 backdrop-blur-sm p-4 rounded-lg border border-white/10">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Filter by Side</h2>
            <div className="flex gap-3">
              {sideOptions.map((side) => (
                <label
                  key={side.value}
                  className={`flex items-center gap-3 p-3 rounded-md cursor-pointer transition-colors ${
                    selectedSides.has(side.value)
                      ? 'bg-neutral-800 border border-neutral-700'
                      : 'hover:bg-neutral-800/50'
                  }`}
                  title={side.label}
                >
                  <input
                    type="checkbox"
                    checked={selectedSides.has(side.value)}
                    onChange={() => toggleSide(side.value)}
                    className="w-4 h-4 accent-blue-600"
                  />
                  <img src={side.image} alt={side.label} className="w-8 h-8 object-contain" />
                </label>
              ))}
            </div>
          </div>
        </div>

        {/* Desktop Side Filter */}
        <div className="hidden lg:block mb-6 bg-neutral-900/50 backdrop-blur-sm p-4 rounded-lg border border-white/10">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Filter by Side</h2>
          <div className="flex gap-3">
            {sideOptions.map((side) => (
              <label
                key={side.value}
                className={`flex items-center gap-3 p-3 rounded-md cursor-pointer transition-colors ${
                  selectedSides.has(side.value)
                    ? 'bg-neutral-800 border border-neutral-700'
                    : 'hover:bg-neutral-800/50'
                }`}
                title={side.label}
              >
                <input
                  type="checkbox"
                  checked={selectedSides.has(side.value)}
                  onChange={() => toggleSide(side.value)}
                  className="w-4 h-4 accent-blue-600"
                />
                <img src={side.image} alt={side.label} className="w-8 h-8 object-contain" />
              </label>
            ))}
          </div>
        </div>

        {loading && <div>Loading nades…</div>}
        {error && <div className="text-red-400">Failed to load nades</div>}
        
        {displayNades.length === 0 && !loading && (
          <div className="bg-neutral-900/50 backdrop-blur-sm p-6 rounded-lg border border-white/10 text-center py-12 text-gray-400">
            No nades found for the selected type.
          </div>
        )}
        
        {displayNades.length > 0 && (
          <div className="bg-neutral-900/50 backdrop-blur-sm p-3 sm:p-6 rounded-lg border border-white/10">
            <div className="grid grid-cols-2 lg:grid-cols-3 gap-2 sm:gap-4">
              {displayNades.map((n) => (
                <NadeCard key={n.id} nade={n} onClick={setActive} mapName={mapName || undefined} />
              ))}
            </div>
          </div>
        )}

        {active && <YouTubePlayer nade={active} onClose={() => setActive(null)} />}
      </div>
    </div>
  );
}

