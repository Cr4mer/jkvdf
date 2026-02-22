import { useState } from 'react';
import { collection, addDoc, doc, updateDoc, deleteDoc } from 'firebase/firestore';
import { db } from '@/firebase';
import { Nade, Cs2Map } from '@/types';
import { useFirestoreCollection } from '@/hooks/useFirestoreCollection';
import { generateTimestampedThumbnailUrl } from '@/utils/youtubeUtils';
import NadeVideoPreview from './NadeVideoPreview';
import { useMobileOptimizedImage } from '@/hooks/useMobileOptimizedImage';
import { useAuth } from '@/hooks/useAuth';
import { normalizeSteamId } from '@/utils/steamWhitelist';

// Format throw method for display
function formatThrowMethod(method: string): string {
  const mapping: Record<string, string> = {
    'left click throw': 'left click',
    'left + right click throw': 'left + right click',
    'jump throw': 'jump throw',
    'jumpthrow+w': 'jumpthrow+w'
  };
  return mapping[method] || method;
}

export default function AdminNades() {
  const { user } = useAuth();
  const { getOptimizedYouTubeThumbnail } = useMobileOptimizedImage();
  const [selectedMap, setSelectedMap] = useState<string>('');
  const [showForm, setShowForm] = useState(false);
  const [editingNade, setEditingNade] = useState<Nade | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    type: 'smoke',
    side: 'both',
    youtubeVideoId: '',
    startSeconds: 0,
    endSeconds: 0,
    thumbnailUrl: '',
    throwMethod: [] as string[],
    tags: '' as string, // comma-separated for input
  });

  const mapsRef = collection(db, 'maps');
  const { data: maps } = useFirestoreCollection<Cs2Map>(mapsRef);

  const nadesRef = selectedMap ? collection(db, `maps/${selectedMap}/nades`) : null;
  const { data: nades, loading } = useFirestoreCollection<Nade>(nadesRef);

  // This function is now imported from youtubeUtils
  // Keeping this for backwards compatibility if needed
  const generateThumbnailUrl = (videoId: string, timestamp: number) => {
    return generateTimestampedThumbnailUrl(videoId, timestamp);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    if (!selectedMap) {
      setError('Please select a map first');
      return;
    }
    if (!user || !user.steamId) {
      setError('You must be logged in to perform this action');
      return;
    }

    // Client-side validation
    if (!formData.name || formData.name.trim().length === 0) {
      setError('Nade name is required');
      return;
    }
    if (formData.name.length > 200) {
      setError('Nade name must be 200 characters or less');
      return;
    }
    const validTypes = ['smoke', 'instant_smoke', 'flash', 'molotov', 'he', 'decoy', 'sæt'];
    if (!validTypes.includes(formData.type)) {
      setError('Invalid nade type');
      return;
    }
    const validSides = ['ct', 't', 'both'];
    if (!validSides.includes(formData.side)) {
      setError('Invalid side');
      return;
    }
    if (!formData.youtubeVideoId || formData.youtubeVideoId.trim().length === 0) {
      setError('YouTube video ID is required');
      return;
    }
    if (!/^[a-zA-Z0-9_-]{11}$/.test(formData.youtubeVideoId)) {
      setError('YouTube video ID must be a valid 11-character ID');
      return;
    }
    if (typeof formData.startSeconds !== 'number' || formData.startSeconds < 0) {
      setError('Start seconds must be a non-negative number');
      return;
    }
    if (formData.endSeconds !== undefined && formData.endSeconds !== 0 && 
        (typeof formData.endSeconds !== 'number' || formData.endSeconds < 0)) {
      setError('End seconds must be a non-negative number if provided');
      return;
    }

    try {
      // Sanitize inputs
      const data: any = {
        name: formData.name.trim().substring(0, 200),
        type: formData.type,
        side: formData.side,
        youtubeVideoId: formData.youtubeVideoId.trim().substring(0, 20),
        startSeconds: formData.startSeconds,
        thumbnailUrl: (formData.thumbnailUrl || generateThumbnailUrl(formData.youtubeVideoId, formData.startSeconds)).substring(0, 500),
        _adminSteamId: normalizeSteamId(user.steamId), // Include admin Steam ID for Firestore rules
      };

      // Only add endSeconds if it's greater than 0
      if (formData.endSeconds > 0) {
        data.endSeconds = formData.endSeconds;
      }

      // Only add throwMethod if it's provided and not empty
      if (formData.throwMethod && formData.throwMethod.length > 0) {
        data.throwMethod = formData.throwMethod.filter((m: string) => typeof m === 'string' && m.length > 1);
      }

      // Tags: comma-separated string -> array (max 20, each trimmed, non-empty)
      const tagStrings = (formData.tags || '').split(',').map((t: string) => t.trim()).filter((t: string) => t.length > 0);
      if (tagStrings.length > 0) {
        data.tags = tagStrings.slice(0, 20);
      }

      if (editingNade) {
        await updateDoc(doc(db, `maps/${selectedMap}/nades`, editingNade.id), data);
      } else {
        await addDoc(collection(db, `maps/${selectedMap}/nades`), data);
      }
      
      setShowForm(false);
      setEditingNade(null);
      setFormData({
        name: '',
        type: 'smoke',
        side: 'both',
        youtubeVideoId: '',
        startSeconds: 0,
        endSeconds: 0,
        thumbnailUrl: '',
        throwMethod: [],
        tags: '',
      });
      setError(null);
    } catch (error: any) {
      console.error('Error saving nade:', error);
      const errorMsg = error.message || 'Failed to save nade';
      setError(errorMsg.substring(0, 200).replace(/api[_-]?key[=:]\s*[\w-]+/gi, 'api_key=***'));
    }
  };

  const handleEdit = (nade: Nade) => {
    setEditingNade(nade);
    const tagArray = Array.isArray(nade.tags) ? nade.tags : [];
    setFormData({
      name: nade.name,
      type: nade.type,
      side: nade.side || 'both',
      youtubeVideoId: nade.youtubeVideoId,
      startSeconds: nade.startSeconds,
      endSeconds: nade.endSeconds || 0,
      thumbnailUrl: nade.thumbnailUrl,
      throwMethod: Array.isArray(nade.throwMethod) ? nade.throwMethod : (nade.throwMethod ? [nade.throwMethod] : []),
      tags: tagArray.join(', '),
    });
    setShowForm(true);
  };

  const handleDelete = async (nadeId: string) => {
    if (!selectedMap) return;
    if (!user || !user.steamId) {
      alert('You must be logged in to delete nades');
      return;
    }
    if (confirm('Delete this nade?')) {
      try {
        // Firestore rules will check admin status
        await deleteDoc(doc(db, `maps/${selectedMap}/nades`, nadeId));
      } catch (error: any) {
        console.error('Error deleting nade:', error);
        const errorMsg = error.message || 'Failed to delete nade';
        alert(errorMsg.substring(0, 200).replace(/api[_-]?key[=:]\s*[\w-]+/gi, 'api_key=***'));
      }
    }
  };

  return (
    <div>
      <div className="mb-6">
        <label className="block text-sm font-medium mb-2">Select Map</label>
        <select
          value={selectedMap}
          onChange={(e) => setSelectedMap(e.target.value)}
          className="px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="">Choose a map...</option>
          {maps?.map((map) => (
            <option key={map.id} value={map.id}>
              {map.name}
            </option>
          ))}
        </select>
      </div>

      {selectedMap && (
        <>
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-xl font-semibold">
              Nades ({nades?.length || 0}) - {maps?.find(m => m.id === selectedMap)?.name}
            </h2>
            <button
              onClick={() => {
                setEditingNade(null);
                setFormData({
                  name: '',
                  type: 'smoke',
                  side: 'both',
                  youtubeVideoId: '',
                  startSeconds: 0,
                  endSeconds: 0,
                  thumbnailUrl: '',
                  throwMethod: [],
                  tags: '',
                });
                setShowForm(true);
              }}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-md text-sm"
            >
              Add Nade
            </button>
          </div>

          {showForm && (
            <div className="bg-neutral-800 rounded-lg p-6 mb-6">
              <h3 className="text-lg font-medium mb-4">
                {editingNade ? 'Edit Nade' : 'Add New Nade'}
              </h3>
              <form onSubmit={handleSubmit} className="space-y-4">
                {error && (
                  <div className="bg-red-900/50 border border-red-500/50 rounded-md p-3 text-sm text-red-200">
                    {error}
                  </div>
                )}
                <div className="grid grid-cols-2 gap-4">
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
                    <label className="block text-sm font-medium mb-2">Type</label>
                    <select
                      value={formData.type}
                      onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                      className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="smoke">Smoke</option>
                      <option value="instant_smoke">Instant Smoke</option>
                      <option value="flash">Flash</option>
                      <option value="molotov">Molotov</option>
                      <option value="he">HE Grenade</option>
                      <option value="decoy">Decoy</option>
                      <option value="sæt">Sæt</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">YouTube Video ID</label>
                  <input
                    type="text"
                    value={formData.youtubeVideoId}
                    onChange={(e) => setFormData({ ...formData, youtubeVideoId: e.target.value })}
                    placeholder="dQw4w9WgXcQ"
                    className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  />
                  <p className="text-xs text-gray-400 mt-1">
                    Just the ID part from https://www.youtube.com/watch?v=VIDEO_ID
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">Side</label>
                  <select
                    value={formData.side}
                    onChange={(e) => setFormData({ ...formData, side: e.target.value as 'ct' | 't' | 'both' })}
                    className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  >
                    <option value="ct">Counter-Terrorist (CT)</option>
                    <option value="t">Terrorist (T)</option>
                    <option value="both">Both Sides</option>
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-2">Start Seconds</label>
                    <input
                      type="number"
                      value={formData.startSeconds}
                      onChange={(e) => setFormData({ ...formData, startSeconds: parseInt(e.target.value) || 0 })}
                      className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-2">End Time (optional)</label>
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <input
                          type="number"
                          placeholder="Minutes"
                          value={Math.floor((formData.endSeconds || 0) / 60)}
                          onChange={(e) => {
                            const minutes = parseInt(e.target.value) || 0;
                            const seconds = (formData.endSeconds || 0) % 60;
                            setFormData({ ...formData, endSeconds: minutes * 60 + seconds });
                          }}
                          className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <span className="text-xs text-gray-400">min</span>
                      </div>
                      <div>
                        <input
                          type="number"
                          placeholder="Seconds"
                          value={(formData.endSeconds || 0) % 60}
                          onChange={(e) => {
                            const secs = parseInt(e.target.value) || 0;
                            const minutes = Math.floor((formData.endSeconds || 0) / 60);
                            setFormData({ ...formData, endSeconds: minutes * 60 + secs });
                          }}
                          className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        <span className="text-xs text-gray-400">sec</span>
                      </div>
                    </div>
                    {formData.endSeconds > 0 && (
                      <p className="text-xs text-gray-400 mt-1">
                        Total: {formData.endSeconds} seconds
                      </p>
                    )}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">Custom Thumbnail URL (optional)</label>
                  <input
                    type="url"
                    value={formData.thumbnailUrl}
                    onChange={(e) => setFormData({ ...formData, thumbnailUrl: e.target.value })}
                    placeholder="Leave empty to auto-generate from video"
                    className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">Tags (optional)</label>
                  <input
                    type="text"
                    value={formData.tags}
                    onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                    placeholder="e.g. execute, retake, one-way (comma-separated)"
                    className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <p className="text-xs text-gray-400 mt-1">Comma-separated tags to categorize the nade.</p>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">Throw Method (optional)</label>
                  <div className="space-y-2">
                    {[
                      'left click throw',
                      'left + right click throw',
                      'jump throw',
                      'jumpthrow+w'
                    ].map((method) => (
                      <label key={method} className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={formData.throwMethod.includes(method)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setFormData({ ...formData, throwMethod: [...formData.throwMethod, method] });
                            } else {
                              setFormData({ ...formData, throwMethod: formData.throwMethod.filter(m => m !== method) });
                            }
                          }}
                          className="w-4 h-4 text-blue-600 bg-neutral-700 border-neutral-600 rounded focus:ring-2 focus:ring-blue-500"
                        />
                        <span className="text-sm">{method}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="flex gap-2">
                  <button
                    type="submit"
                    className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-md text-sm"
                  >
                    {editingNade ? 'Update' : 'Create'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setShowForm(false);
                      setEditingNade(null);
                      setFormData({
                        name: '',
                        type: 'smoke',
                        side: 'both',
                        youtubeVideoId: '',
                        startSeconds: 0,
                        endSeconds: 0,
                        thumbnailUrl: '',
                        throwMethod: [],
                        tags: '',
                      });
                    }}
                    className="px-4 py-2 bg-gray-600 hover:bg-gray-700 rounded-md text-sm"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          )}

          {loading && <div>Loading nades...</div>}
          
          <div className="grid gap-4">
                         {nades?.map((nade) => {
               const thumbnailUrl = nade.thumbnailUrl || getOptimizedYouTubeThumbnail(nade.youtubeVideoId);
               
               return (
                 <div key={nade.id} className="bg-neutral-800 rounded-lg p-4 flex items-center justify-between">
                   <div className="flex items-center gap-4">
                    <div className="relative w-24 h-16 overflow-hidden rounded">
                      <NadeVideoPreview
                        id={nade.id || `${nade.youtubeVideoId}-${nade.startSeconds}`}
                        videoId={nade.youtubeVideoId}
                        startSeconds={nade.startSeconds}
                        endSeconds={nade.endSeconds}
                        className="w-full h-full"
                        thumbnailUrl={thumbnailUrl}
                      />
                    </div>
                    <div>
                      <h3 className="font-medium">{nade.name}</h3>
                      <p className="text-sm text-gray-400">
                        {nade.type === 'instant_smoke' ? 'Instant Smoke' : nade.type} • {nade.side === 'ct' ? 'CT' : nade.side === 't' ? 'T' : 'Both'} • {nade.startSeconds}s{nade.endSeconds ? `-${nade.endSeconds}s` : ''}
                      </p>
                      {nade.tags && nade.tags.length > 0 && (
                        <p className="text-xs text-amber-400/90 mt-1">{nade.tags.join(', ')}</p>
                      )}
                      {nade.throwMethod && (() => {
                        const methods = Array.isArray(nade.throwMethod) 
                          ? nade.throwMethod 
                          : [nade.throwMethod];
                        
                        // Filter out single character items (corrupted data) and keep only meaningful strings
                        const validMethods = methods.filter(m => String(m).length > 1);
                        
                        if (validMethods.length > 0) {
                          const displayMethods = validMethods.map(formatThrowMethod);
                          return <p className="text-xs text-blue-400 mt-1">{displayMethods.join(' & ')}</p>;
                        }
                        
                        return null;
                      })()}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleEdit(nade)}
                      className="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDelete(nade.id)}
                      className="px-3 py-1 bg-red-600 hover:bg-red-700 rounded text-sm"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
