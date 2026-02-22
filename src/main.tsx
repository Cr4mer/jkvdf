import React from 'react';
import ReactDOM from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import './styles.css';
import App from './App';
import HomePage from './pages/HomePage';
import MapListPage from './pages/MapListPage';
import NadeGalleryPage from './pages/NadeGalleryPage';
import RoosterPage from './pages/RoosterPage';
import AdminPage from './pages/AdminPage';
import TrainingPage from './pages/TrainingPage';
import PastTrainingPage from './pages/PastTrainingPage';
import { ActiveVideoProvider } from './contexts/ActiveVideoContext';

const router = createBrowserRouter([
  {
    path: '/',
    element: <App />,
    children: [
      { index: true, element: <HomePage /> },
      { path: 'maps', element: <MapListPage /> },
      { path: 'map/:mapId', element: <NadeGalleryPage /> },
      { path: 'rooster', element: <RoosterPage /> },
      { path: 'admin', element: <AdminPage /> },
      { path: 'training', element: <TrainingPage /> },
      { path: 'training/past', element: <PastTrainingPage /> },
      { path: 'steam-callback', element: <HomePage /> }, // Callback route handled by App.tsx
    ],
  },
]);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ActiveVideoProvider>
      <RouterProvider router={router} />
    </ActiveVideoProvider>
  </React.StrictMode>,
);


