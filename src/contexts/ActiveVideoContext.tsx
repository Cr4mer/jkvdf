import { createContext, useContext, useState, ReactNode } from 'react';

type ActiveVideoContextType = {
  activeVideoId: string | null;
  setActiveVideoId: (id: string | null) => void;
};

const ActiveVideoContext = createContext<ActiveVideoContextType | undefined>(undefined);

export function ActiveVideoProvider({ children }: { children: ReactNode }) {
  const [activeVideoId, setActiveVideoId] = useState<string | null>(null);

  return (
    <ActiveVideoContext.Provider value={{ activeVideoId, setActiveVideoId }}>
      {children}
    </ActiveVideoContext.Provider>
  );
}

export function useActiveVideo() {
  const context = useContext(ActiveVideoContext);
  if (context === undefined) {
    throw new Error('useActiveVideo must be used within an ActiveVideoProvider');
  }
  return context;
}

