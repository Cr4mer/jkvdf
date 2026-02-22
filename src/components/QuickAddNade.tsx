import { useState } from 'react';
import { collection, addDoc } from 'firebase/firestore';
import { db } from '@/firebase';
import { Cs2Map } from '@/types';
import { useFirestoreCollection } from '@/hooks/useFirestoreCollection';
import { extractYouTubeVideoId, extractYouTubeTimestamp, generateThumbnailUrl, generateTimestampedThumbnailUrl } from '@/utils/youtubeUtils';
import { useAuth } from '@/hooks/useAuth';
import { normalizeSteamId } from '@/utils/steamWhitelist';

type Step = 'url' | 'details' | 'complete';

export default function QuickAddNade() {
  const { user } = useAuth();
  const [step, setStep] = useState<Step>('url');
  const [youtubeUrl, setYoutubeUrl] = useState('');
  const [videoId, setVideoId] = useState('');
  const [extractedTimestamp, setExtractedTimestamp] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [formData, setFormData] = useState<{
    name: string;
    type: 'smoke' | 'instant_smoke' | 'flash' | 'molotov' | 'he' | 'decoy' | string;
    side: 'ct' | 't' | 'both';
    mapId: string;
    startSeconds: number;
    endSeconds: number;
    throwMethod: string[];
    tags: string;
  }>({
    name: '',
    type: 'smoke',
    side: 'both',
    mapId: '',
    startSeconds: 0,
    endSeconds: 0,
    throwMethod: [],
    tags: '',
  });

  const mapsRef = collection(db, 'maps');
  const { data: maps } = useFirestoreCollection<Cs2Map>(mapsRef);

  const handleUrlSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    const extractedVideoId = extractYouTubeVideoId(youtubeUrl);
    const timestamp = extractYouTubeTimestamp(youtubeUrl);
    
    if (!extractedVideoId) {
      alert('Invalid YouTube URL. Please check the URL and try again.');
      return;
    }
    
    setVideoId(extractedVideoId);
    setExtractedTimestamp(timestamp);
    setFormData(prev => ({ ...prev, startSeconds: timestamp }));
    setStep('details');
  };

  const handleDetailsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    if (!user || !user.steamId) {
      setError('You must be logged in to add nades');
      return;
    }
    
    if (!formData.mapId || !formData.name) {
      setError('Please fill in all required fields.');
      return;
    }

    // Validation
    if (formData.name.length > 200) {
      setError('Nade name must be 200 characters or less');
      return;
    }
    if (!/^[a-zA-Z0-9_-]{11}$/.test(videoId)) {
      setError('Invalid YouTube video ID');
      return;
    }
    if (typeof formData.startSeconds !== 'number' || formData.startSeconds < 0) {
      setError('Start seconds must be a non-negative number');
      return;
    }

    try {
      const nadeData: any = {
        name: formData.name.trim().substring(0, 200),
        type: formData.type,
        side: formData.side,
        youtubeVideoId: videoId.substring(0, 20),
        startSeconds: formData.startSeconds,
        thumbnailUrl: generateTimestampedThumbnailUrl(videoId, formData.startSeconds).substring(0, 500),
        _adminSteamId: normalizeSteamId(user.steamId), // Include admin Steam ID for Firestore rules
      };

      // Only add endSeconds if it's greater than 0
      if (formData.endSeconds > 0) {
        nadeData.endSeconds = formData.endSeconds;
      }

      // Only add throwMethod if it's provided and not empty
      if (formData.throwMethod && formData.throwMethod.length > 0) {
        nadeData.throwMethod = formData.throwMethod.filter((m: string) => typeof m === 'string' && m.length > 1);
      }

      const tagStrings = (formData.tags || '').split(',').map((t: string) => t.trim()).filter((t: string) => t.length > 0);
      if (tagStrings.length > 0) {
        nadeData.tags = tagStrings.slice(0, 20);
      }

      await addDoc(collection(db, `maps/${formData.mapId}/nades`), nadeData);
      
      setStep('complete');
      setError(null);
    } catch (error: any) {
      console.error('Error creating nade:', error);
      const errorMsg = error.message || 'Failed to create nade. Please try again.';
      setError(errorMsg.substring(0, 200).replace(/api[_-]?key[=:]\s*[\w-]+/gi, 'api_key=***'));
    }
  };

  const reset = () => {
    setStep('url');
    setYoutubeUrl('');
    setVideoId('');
    setExtractedTimestamp(0);
    setFormData({
      name: '',
      type: 'smoke',
      side: 'both',
      mapId: '',
      startSeconds: 0,
      endSeconds: 0,
      throwMethod: [],
      tags: '',
    });
  };

  if (step === 'url') {
    return (
      <div className="bg-neutral-800 rounded-lg p-6">
        <h3 className="text-lg font-medium mb-4">Quick Add Nade</h3>
        <p className="text-sm text-gray-400 mb-4">
          Paste a YouTube URL and we'll extract the video ID and timestamp automatically.
        </p>
        
        <form onSubmit={handleUrlSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">YouTube URL</label>
            <input
              type="url"
              value={youtubeUrl}
              onChange={(e) => setYoutubeUrl(e.target.value)}
              placeholder="https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=31s"
              className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
            <p className="text-xs text-gray-400 mt-1">
              Supports: youtube.com/watch?v=, youtu.be/, youtube.com/embed/, etc.
            </p>
          </div>
          
          <button
            type="submit"
            className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-md text-sm font-medium"
          >
            Extract Video Info
          </button>
        </form>
      </div>
    );
  }

  if (step === 'details') {
    return (
      <div className="bg-neutral-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-medium">Nade Details</h3>
          <button
            onClick={reset}
            className="text-sm text-gray-400 hover:text-white"
          >
            ← Back to URL
          </button>
        </div>
        
        <div className="mb-4 p-3 bg-neutral-700 rounded-md">
          <p className="text-sm text-gray-300">
            <strong>Video ID:</strong> {videoId}
          </p>
          <p className="text-sm text-gray-300">
            <strong>Detected timestamp:</strong> {extractedTimestamp}s
          </p>
        </div>

        <form onSubmit={handleDetailsSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Nade Name *</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="CT Smoke"
                className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">Type *</label>
              <select
                value={formData.type}
                onChange={(e) => setFormData({ ...formData, type: e.target.value as any })}
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
            <label className="block text-sm font-medium mb-2">Tags (optional)</label>
            <input
              type="text"
              value={formData.tags}
              onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
              placeholder="e.g. execute, retake (comma-separated)"
              className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Map *</label>
            <select
              value={formData.mapId}
              onChange={(e) => setFormData({ ...formData, mapId: e.target.value })}
              className="w-full px-3 py-2 bg-neutral-700 border border-neutral-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            >
              <option value="">Select a map...</option>
              {maps?.map((map) => (
                <option key={map.id} value={map.id}>
                  {map.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Side *</label>
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
              className="flex-1 px-4 py-2 bg-green-600 hover:bg-green-700 rounded-md text-sm font-medium"
            >
              Create Nade
            </button>
            <button
              type="button"
              onClick={reset}
              className="px-4 py-2 bg-gray-600 hover:bg-gray-700 rounded-md text-sm"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    );
  }

  if (step === 'complete') {
    return (
      <div className="bg-green-900/20 border border-green-500/50 rounded-lg p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-8 h-8 bg-green-600 rounded-full flex items-center justify-center">
            ✓
          </div>
          <h3 className="text-lg font-medium text-green-400">Nade Created Successfully!</h3>
        </div>
        
        <p className="text-sm text-gray-300 mb-4">
          Your nade "{formData.name}" has been added to {maps?.find(m => m.id === formData.mapId)?.name}.
        </p>
        
        <button
          onClick={reset}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-md text-sm font-medium"
        >
          Add Another Nade
        </button>
      </div>
    );
  }

  return null;
}
