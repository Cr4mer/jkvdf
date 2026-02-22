import { Outlet, Link, useLocation } from 'react-router-dom';
import { useEffect } from 'react';
import AdminButton from '@/components/AdminButton';
import { useAuth } from '@/hooks/useAuth';
import SoundCloudPlayer from '@/components/SoundCloudPlayer';

export default function App() {
  const location = useLocation();
  const { handleSteamCallback } = useAuth();

  // Handle Steam callback when on /steam-callback route
  useEffect(() => {
    if (location.pathname === '/steam-callback') {
      handleSteamCallback().catch((error) => {
        console.error('Steam callback error:', error);
        alert(`Login failed: ${error.message}`);
        // Redirect to home
        window.location.href = '/';
      });
    }
  }, [location.pathname, handleSteamCallback]);
  
  return (
    <div className="min-h-screen bg-neutral-950 text-white relative">
      {/* Semi-transparent background image */}
      <div 
        className="fixed inset-0 bg-cover bg-center bg-no-repeat opacity-30 pointer-events-none"
        style={{ backgroundImage: 'url(/poster.png)' }}
        aria-hidden
      />
      <header className="sticky top-0 z-20 border-b border-white/10 bg-neutral-950/80 backdrop-blur relative">
        <div className="mx-auto max-w-6xl px-4 py-3 flex items-center">
          {/* Left: Logo */}
          <div className="flex-1">
            <Link to="/" className="flex items-center gap-2">
              <img src="/logo.png" alt="Logo" className="h-8 w-auto" onError={(e) => {
                const img = e.target as HTMLImageElement;
                if (img.src.endsWith('.png')) {
                  img.src = '/logo.jpg';
                } else if (img.src.endsWith('.jpg')) {
                  img.src = '/logo.svg';
                } else {
                  img.style.display = 'none';
                }
              }} />
            </Link>
          </div>
          
          {/* Center: Calendar icon link to training page - desktop only */}
          <div className="flex-1 flex justify-center">
            <Link 
              to="/training" 
              className="hidden md:block p-2 text-gray-400 hover:text-white hover:bg-neutral-800 rounded-md transition-colors"
              title="Training Sessions"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
            </Link>
          </div>
          
          {/* Right: Admin button */}
          <div className="flex-1 flex justify-end">
            <AdminButton />
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6 relative pb-28">
        <Outlet />
      </main>
      
      {/* SoundCloud Player - available on all pages */}
      <SoundCloudPlayer />
    </div>
  );
}

