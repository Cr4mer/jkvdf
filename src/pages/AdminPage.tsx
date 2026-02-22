import { useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { Navigate } from 'react-router-dom';
import AdminMaps from '@/components/AdminMaps';
import AdminNades from '@/components/AdminNades';
import QuickAddNade from '@/components/QuickAddNade';

export default function AdminPage() {
  const { user, isAdmin, loading } = useAuth();
  const [activeTab, setActiveTab] = useState<'quick-add' | 'maps' | 'nades'>('quick-add');

  if (loading) {
    return <div className="text-center py-8">Loading...</div>;
  }

  if (!user || !isAdmin) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="mb-6">
        <h1 className="text-3xl font-bold mb-2">Admin Panel</h1>
        <p className="text-gray-400">Manage maps and nades</p>
      </div>

      <div className="flex gap-1 mb-6 bg-neutral-800 rounded-lg p-1">
        <button
          onClick={() => setActiveTab('quick-add')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'quick-add'
              ? 'bg-neutral-700 text-white'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          Quick Add Nade
        </button>
        <button
          onClick={() => setActiveTab('maps')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'maps'
              ? 'bg-neutral-700 text-white'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          Maps
        </button>
        <button
          onClick={() => setActiveTab('nades')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'nades'
              ? 'bg-neutral-700 text-white'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          Nades
        </button>
      </div>

      {activeTab === 'quick-add' && <QuickAddNade />}
      {activeTab === 'maps' && <AdminMaps />}
      {activeTab === 'nades' && <AdminNades />}
    </div>
  );
}
