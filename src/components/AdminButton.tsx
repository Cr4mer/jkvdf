import { useState, useRef, useEffect } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { useNavigate } from 'react-router-dom';

export default function AdminButton() {
  const navigate = useNavigate();
  const { user, isAdmin, startSteamLogin, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close menu when clicking outside
  useEffect(() => {
    if (!menuOpen) return;
    const handleClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [menuOpen]);

  const handleSteamLogin = () => {
    startSteamLogin();
  };

  if (!user) {
    return (
      <div className="relative flex flex-col items-end gap-0.5">
        <button
          onClick={handleSteamLogin}
          className="p-2 text-gray-400 hover:text-white hover:bg-neutral-800 rounded-md transition-colors"
          title="You'll sign in on Steam's website. We only receive your public Steam ID—we never see your password."
        >
          <img src="/STEAM.png" alt="Steam Login" className="h-5 w-5" />
        </button>
        <span className="text-[10px] text-gray-500 max-w-[140px] text-right leading-tight">
          Sign in on Steam&apos;s site. We never see your password.
        </span>
      </div>
    );
  }

  if (!isAdmin) {
    return (
      <div className="flex items-center gap-2">
        <span className="text-xs text-gray-400">Not admin</span>
        <button
          onClick={logout}
          className="p-2 text-gray-400 hover:text-white hover:bg-neutral-800 rounded-md transition-colors"
          title="Logout"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
          </svg>
        </button>
      </div>
    );
  }

  const openAdmin = (path: string) => {
    setMenuOpen(false);
    navigate(path);
  };

  return (
    <div className="flex items-center gap-2" ref={menuRef}>
      <span className="text-xs text-green-400">Admin</span>
      <div className="relative">
        <button
          type="button"
          onClick={() => setMenuOpen((open) => !open)}
          className="p-2 min-w-[2.5rem] min-h-[2.5rem] flex items-center justify-center text-green-400 hover:text-green-300 hover:bg-neutral-800 rounded-md transition-colors cursor-pointer"
          title="Admin menu"
          aria-label="Open Admin menu"
          aria-expanded={menuOpen}
          aria-haspopup="menu"
        >
          <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
        </button>
        {menuOpen && (
          <div
            role="menu"
            className="absolute right-0 top-full mt-1 py-1 min-w-[180px] bg-neutral-800 border border-white/10 rounded-lg shadow-xl z-30"
          >
            <button
              type="button"
              role="menuitem"
              onClick={() => openAdmin('/admin')}
              className="w-full px-4 py-2.5 text-left text-sm text-white hover:bg-neutral-700 rounded-t-lg"
            >
              Quick Add Nade
            </button>
            <button
              type="button"
              role="menuitem"
              onClick={() => openAdmin('/admin')}
              className="w-full px-4 py-2.5 text-left text-sm text-gray-300 hover:bg-neutral-700 rounded-b-lg"
            >
              Admin Panel
            </button>
          </div>
        )}
      </div>
      <button
        onClick={logout}
        className="p-2 text-gray-400 hover:text-white hover:bg-neutral-800 rounded-md transition-colors"
        title="Logout"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
        </svg>
      </button>
    </div>
  );
}
