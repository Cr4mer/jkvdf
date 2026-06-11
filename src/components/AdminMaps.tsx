import { useState } from 'react';
import { collection, addDoc, doc, updateDoc, deleteDoc } from 'firebase/firestore';
import { db } from '@/firebase';
import { Cs2Map } from '@/types';
import { useFirestoreCollection } from '@/hooks/useFirestoreCollection';
import { useAuth } from '@/hooks/useAuth';
import { normalizeSteamId } from '@/utils/steamWhitelist';
import { versionedAsset } from '@/utils/assets';

export default function AdminMaps() {
  const { user } = useAuth();
  const [showForm, setShowForm] = useState(false);
  const [editingMap, setEditingMap] = useState<Cs2Map | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    slug: '',
    thumbnailUrl: '',
  });
  const [error, setError] = useState<string | null>(null);

  const mapsRef = collection(db, 'maps');
  const { data: maps, loading } = useFirestoreCollection<Cs2Map>(mapsRef);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Client-side validation
    if (!formData.name || formData.name.trim().length === 0) {
      setError('Map name is required');
      return;
    }
    if (formData.name.length > 100) {
      setError('Map name must be 100 characters or less');
      return;
    }
    if (!formData.slug || formData.slug.trim().length === 0) {
      setError('Map slug is required');
      return;
    }
    if (formData.slug.length > 50) {
      setError('Map slug must be 50 characters or less');
      return;
    }
    if (!/^[a-z0-9-]+$/.test(formData.slug)) {
      setError('Slug can only contain lowercase letters, numbers, and hyphens');
      return;
    }
    if (!formData.thumbnailUrl || formData.thumbnailUrl.trim().length === 0) {
      setError('Thumbnail URL is required');
      return;
    }
    if (formData.thumbnailUrl.length > 500) {
      setError('Thumbnail URL must be 500 characters or less');
      return;
    }
    if (!user || !user.steamId) {
      setError('You must be logged in to perform this action');
      return;
    }

    try {
      // Sanitize inputs
      const sanitizedData = {
        name: formData.name.trim().substring(0, 100),
        slug: formData.slug.trim().toLowerCase().substring(0, 50),
        thumbnailUrl: formData.thumbnailUrl.trim().substring(0, 500),
        _adminSteamId: normalizeSteamId(user.steamId), // Include admin Steam ID for Firestore rules
      };

      if (editingMap) {
        await updateDoc(doc(db, 'maps', editingMap.id), sanitizedData);
      } else {
        await addDoc(collection(db, 'maps'), sanitizedData);
      }
      setShowForm(false);
      setEditingMap(null);
      setFormData({ name: '', slug: '', thumbnailUrl: '' });
      setError(null);
    } catch (error: any) {
      console.error('Error saving map:', error);
      let errorMsg = error?.message || 'Failed to save map';
      if (/permission|denied|forbidden/i.test(errorMsg)) {
        const steamId = user?.steamId ? normalizeSteamId(user.steamId) : 'YOUR_STEAM_ID';
        errorMsg = `Permission denied. In Firestore: create document "admins/allowlist" with field "steamIds" (array) containing "${steamId}", then deploy rules.`;
      } else {
        errorMsg = errorMsg.substring(0, 200).replace(/api[_-]?key[=:]\s*[\w-]+/gi, 'api_key=***');
      }
      setError(errorMsg);
    }
  };

  const handleEdit = (map: Cs2Map) => {
    setEditingMap(map);
    setFormData({
      name: map.name,
      slug: map.slug,
      thumbnailUrl: map.thumbnailUrl,
    });
    setShowForm(true);
  };

  const handleDelete = async (mapId: string) => {
    if (!user || !user.steamId) {
      alert('You must be logged in to delete maps');
      return;
    }
    if (confirm('Delete this map? This will also delete all nades in this map.')) {
      try {
        // Firestore rules will check admin status
        await deleteDoc(doc(db, 'maps', mapId));
      } catch (error: any) {
        console.error('Error deleting map:', error);
        let errorMsg = error?.message || 'Failed to delete map';
        if (/permission|denied|forbidden/i.test(errorMsg)) {
          const steamId = user?.steamId ? normalizeSteamId(user.steamId) : 'YOUR_STEAM_ID';
          errorMsg = `Permission denied. In Firestore: create document "admins/allowlist" with field "steamIds" (array) containing "${steamId}", then deploy rules.`;
        } else {
          errorMsg = errorMsg.substring(0, 200).replace(/api[_-]?key[=:]\s*[\w-]+/gi, 'api_key=***');
        }
        alert(errorMsg);
      }
    }
  };

  if (loading) return <div>Loading maps...</div>;

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-xl font-semibold">Maps ({maps?.length || 0})</h2>
        <button
          onClick={() => {
            setEditingMap(null);
            setFormData({ name: '', slug: '', thumbnailUrl: '' });
            setShowForm(true);
          }}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-md text-sm"
        >
          Add Map
        </button>
      </div>

      {showForm && (
        <div className="bg-neutral-800 rounded-lg p-6 mb-6">
          <h3 className="text-lg font-medium mb-4">
            {editingMap ? 'Edit Map' : 'Add New Map'}
          </h3>
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="bg-red-900/50 border border-red-500/50 rounded-md p-3 text-sm text-red-200">
                {error}
              </div>
            )}
            <div>
              <label className="block text-sm font-medium mb-2">Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Slug</label>
              <input
                type="text"
                value={formData.slug}
                onChange={(e) => setFormData({ ...formData, slug: e.target.value })}
                className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Thumbnail URL (or local path)</label>
              <input
                type="text"
                value={formData.thumbnailUrl}
                onChange={(e) => setFormData({ ...formData, thumbnailUrl: e.target.value })}
                placeholder="e.g., /inferno.jpeg or https://example.com/image.jpg"
                className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            <div className="flex gap-2">
              <button
                type="submit"
                className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-md text-sm"
              >
                {editingMap ? 'Update' : 'Create'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowForm(false);
                  setEditingMap(null);
                  setFormData({ name: '', slug: '', thumbnailUrl: '' });
                }}
                className="px-4 py-2 bg-gray-600 hover:bg-gray-700 rounded-md text-sm"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="grid gap-4">
        {maps?.map((map) => (
          <div key={map.id} className="bg-neutral-800 rounded-lg p-4 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <img
                src={versionedAsset(map.thumbnailUrl)}
                alt={map.name}
                className="w-16 h-12 object-cover rounded"
              />
              <div>
                <h3 className="font-medium">{map.name}</h3>
                <p className="text-sm text-gray-400">/{map.slug}</p>
              </div>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => handleEdit(map)}
                className="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm"
              >
                Edit
              </button>
              <button
                onClick={() => handleDelete(map.id)}
                className="px-3 py-1 bg-red-600 hover:bg-red-700 rounded text-sm"
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
