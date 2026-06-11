import { Link } from 'react-router-dom';
import { collection } from 'firebase/firestore';
import { useState, useEffect } from 'react';
import { db } from '@/firebase';
import { Cs2Map } from '@/types';
import { useFirestoreCollection } from '@/hooks/useFirestoreCollection';
import RoosterPreview from '@/components/RoosterPreview';
import { versionedAsset } from '@/utils/assets';

export default function HomePage() {
  const mapsRef = collection(db, 'maps');
  const { data: maps, loading, error } = useFirestoreCollection<Cs2Map>(mapsRef);
  const [showBurgerMenu, setShowBurgerMenu] = useState(false);

  // Close burger menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest('.burger-menu') && !target.closest('.burger-button')) {
        setShowBurgerMenu(false);
      }
    };

    if (showBurgerMenu) {
      document.addEventListener('click', handleClickOutside);
      return () => document.removeEventListener('click', handleClickOutside);
    }
  }, [showBurgerMenu]);

  // Mobile: Empty landing page
  if (typeof window !== 'undefined' && window.innerWidth < 768) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        {/* Mobile Burger Menu Button */}
        <div className="fixed top-[64px] right-4 z-50">
          <button
            onClick={() => setShowBurgerMenu(!showBurgerMenu)}
            className="burger-button bg-neutral-900/90 backdrop-blur-sm border border-white/10 rounded-lg p-3 hover:bg-neutral-800 transition-colors"
            aria-label="Toggle menu"
          >
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {showBurgerMenu ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              )}
            </svg>
          </button>
        </div>

        {/* Mobile Burger Menu Dropdown */}
        {showBurgerMenu && (
          <div className="burger-menu fixed top-[128px] right-4 z-40 bg-neutral-900/95 backdrop-blur-sm border border-white/10 rounded-lg shadow-xl min-w-[200px]">
            <nav className="p-2">
              <Link
                to="/rooster"
                onClick={() => setShowBurgerMenu(false)}
                className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-neutral-800 transition-colors text-white"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                <span className="font-medium">Performance Center</span>
              </Link>
              <Link
                to="/maps"
                onClick={() => setShowBurgerMenu(false)}
                className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-neutral-800 transition-colors text-white mt-1"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 10l-2 1m0 0l-2-1m2 1v2.5M20 7l-2 1m2-1l-2-1m2 1v2.5M14 4l-2-1-2 1M4 7l2-1M4 7l2 1M4 7v2.5M12 21l-2-1m2 1l2-1m-2 1v-2.5M6 18l-2-1v-2.5M18 18l2-1v-2.5" />
                </svg>
                <span className="font-medium">Nades</span>
              </Link>
              <Link
                to="/training"
                onClick={() => setShowBurgerMenu(false)}
                className="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-neutral-800 transition-colors text-white mt-1"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
                <span className="font-medium">Training</span>
              </Link>
            </nav>
          </div>
        )}
      </div>
    );
  }

  // Desktop: Normal view with maps
  return (
    <div className="max-w-4xl mx-auto mt-12 sm:mt-60 px-4 sm:px-0">
      {/* Loading State */}
      {loading && <div className="text-center">Loading maps...</div>}
      
      {/* Error State */}
      {error && (
        <div className="text-center text-red-400">
          Failed to load maps: {error.message}
        </div>
      )}

      {/* Maps Grid */}
      {maps && (
        <div className="border border-white/10 rounded-lg p-6 bg-neutral-900/50 backdrop-blur-sm">
          <p className="text-center text-gray-400 mb-6">Choose a map to browse nades</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
            {maps.map((map) => (
              <Link
                key={map.id}
                to={`/map/${map.id}`}
                className="group rounded-lg overflow-hidden border border-white/10 hover:border-white/20 focus:outline-none focus:ring-2 focus:ring-white/30 transition-all hover:scale-105"
              >
                <div className="aspect-video bg-neutral-900 relative">
                  <img
                    src={versionedAsset(map.thumbnailUrl)}
                    alt={map.name}
                    className="w-full h-full object-cover"
                  />
                  <div className="absolute inset-0 bg-black/0 group-hover:bg-black/30 transition-colors" />
                </div>
                <div className="p-4 text-center">
                  <h2 className="font-semibold text-lg">{map.name}</h2>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Rooster Preview */}
      <RoosterPreview />
    </div>
  );
}
