import { useState, useEffect } from 'react';
import { doc, getDoc } from 'firebase/firestore';
import { db } from '@/firebase';
import { isWhitelisted, getFaceitName, normalizeSteamId } from '@/utils/steamWhitelist';
import { initiateSteamLogin, parseSteamIdFromCallback } from '@/utils/steamAuth';

type User = {
  steamId: string;
  displayName: string;
};

export function useAuth() {
  const steamIdFromStorage = typeof window !== 'undefined' ? localStorage.getItem('steamId') : null;
  const [user, setUser] = useState<User | null>(
    steamIdFromStorage ? { steamId: steamIdFromStorage, displayName: getFaceitName(steamIdFromStorage) } : null
  );
  const [adminCheckComplete, setAdminCheckComplete] = useState(false);
  const [isAdmin, setIsAdmin] = useState<boolean>(false);

  // Admin status: Firestore admins collection OR client whitelist (so whitelisted IDs are always admin)
  useEffect(() => {
    if (!user?.steamId) {
      setIsAdmin(false);
      setAdminCheckComplete(true);
      return;
    }
    setAdminCheckComplete(false);
    const id = normalizeSteamId(user.steamId);
    getDoc(doc(db, 'admins', id))
      .then((snap) => {
        setIsAdmin(snap.exists() || isWhitelisted(user.steamId));
        setAdminCheckComplete(true);
      })
      .catch(() => {
        setIsAdmin(isWhitelisted(user.steamId));
        setAdminCheckComplete(true);
      });
  }, [user?.steamId]);

  // Show loading until we know admin status when user is logged in
  const loading = !!user && !adminCheckComplete;

  // Start Steam OpenID authentication flow
  const startSteamLogin = () => {
    initiateSteamLogin();
  };

  // Handle Steam callback and complete login
  const handleSteamCallback = async () => {
    try {
      // Parse Steam ID from callback URL
      const { steamId, isValid } = parseSteamIdFromCallback();

      if (!isValid || !steamId) {
        throw new Error('Failed to parse Steam ID from callback');
      }

      // Check if Steam ID is admin: Firestore admins collection (or client whitelist fallback)
      const adminRef = doc(db, 'admins', normalizeSteamId(steamId));
      const adminSnap = await getDoc(adminRef);
      const isAdminUser = adminSnap.exists() || isWhitelisted(steamId);

      if (!isAdminUser) {
        throw new Error('Steam ID not whitelisted for admin access.');
      }

      // Store Steam ID in localStorage instead of Firebase auth
      localStorage.setItem('steamId', steamId);

      // Force refresh to update auth state
      window.location.href = '/';
    } catch (error: any) {
      if (import.meta.env.DEV) {
        console.error('Steam callback failed:', error);
      }
      throw error;
    }
  };

  const logout = async () => {
    try {
      localStorage.removeItem('steamId');
      setUser(null);
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Logout failed:', error);
      }
    }
  };

  return {
    user,
    loading,
    startSteamLogin,
    handleSteamCallback,
    logout,
    isAdmin,
  };
}
