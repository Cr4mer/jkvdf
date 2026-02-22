import { useEffect, useState } from 'react';
import { collection, onSnapshot, orderBy, query } from 'firebase/firestore';
import { db } from '@/firebase';
import { TrainingSession } from '@/types';

export default function PastTrainingPage() {
  const [sessions, setSessions] = useState<TrainingSession[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const sessionsRef = collection(db, 'trainingSessions');
    const q = query(sessionsRef, orderBy('date', 'desc'));
    const unsub = onSnapshot(q, (snap) => {
      const all = snap.docs.map((d) => ({ id: d.id, ...d.data() })) as TrainingSession[];
      setSessions(all);
      setLoading(false);
    });
    return () => unsub();
  }, []);

  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);

  const pastSessions = sessions.filter((s) => {
    const d = new Date(s.date);
    d.setHours(0, 0, 0, 0);
    return d < todayStart;
  });

  const currentYear = new Date().getFullYear();
  const trainingsThisYear = sessions.filter((s) => {
    const d = new Date(s.date);
    return d.getFullYear() === currentYear;
  }).length;

  // Count how many past sessions each person attended (only "can go" counts as tilmelding)
  const attendanceCount = (() => {
    const bySteamId: Record<string, { count: number; displayName: string }> = {};
    pastSessions.forEach((session) => {
      session.responses?.forEach((r) => {
        if (r.status === 'cannot_go') return;
        const id = r.steamId || r.displayName || r.id;
        if (!id) return;
        if (!bySteamId[id]) bySteamId[id] = { count: 0, displayName: r.displayName || id };
        bySteamId[id].count += 1;
        bySteamId[id].displayName = r.displayName || bySteamId[id].displayName;
      });
    });
    return Object.entries(bySteamId)
      .map(([_, v]) => v)
      .sort((a, b) => b.count - a.count);
  })();

  const getAttendingCount = (responses: TrainingSession['responses'] | undefined) =>
    responses?.filter((r) => r.status !== 'cannot_go').length ?? 0;

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('da-DK', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  const statusLabel = (status: string) => {
    switch (status) {
      case 'cannot_go': return 'Kan ikke';
      case 'can_go_online': return 'Kan online';
      case 'can_go_hall': return 'Kan i forening';
      case 'can_go_both': return 'Kan i forening';
      default: return status;
    }
  };

  return (
    <div className="max-w-6xl mx-auto">
      <div className="mb-8">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold mb-2">Tidligere træningssessioner</h1>
            <p className="text-gray-400">Arkiv over tidligere træninger</p>
          </div>
          <a
            href="/training"
            className="px-3 py-2 h-10 mt-1 bg-neutral-800 hover:bg-neutral-700 border border-white/10 rounded-md text-sm text-gray-200 transition-colors w-full sm:w-auto text-center"
          >
            ← Tilbage til kommende
          </a>
        </div>
      </div>

      <div className="mb-6 space-y-4">
        <div className="p-4 rounded-lg border border-white/10 bg-neutral-900/50">
          <p className="text-gray-300">
            Træninger i år: <span className="font-semibold">{trainingsThisYear}</span>
          </p>
        </div>
        {attendanceCount.length > 0 && (
          <div className="p-4 rounded-lg border border-white/10 bg-neutral-900/50">
            <h2 className="text-lg font-semibold mb-3 text-gray-200">Antal tilmeldinger (tidligere sessioner)</h2>
            <p className="text-sm text-gray-400 mb-3">Hvor mange gange hver person har deltaget i en tidligere træning (kun når de kunne komme)</p>
            <div className="flex flex-wrap gap-x-6 gap-y-2">
              {attendanceCount.map(({ displayName, count }) => (
                <span key={displayName} className="text-gray-300">
                  <span className="font-medium text-white">{displayName}</span>
                  <span className="text-gray-400">: {count}</span>
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {loading ? (
        <div className="text-center py-8 text-gray-400">Indlæser...</div>
      ) : pastSessions.length === 0 ? (
        <div className="text-center py-8 text-gray-400">Ingen tidligere træningssessioner</div>
      ) : (
        <div className="space-y-4">
          {pastSessions.map((session) => (
            <div key={session.id} className="bg-neutral-900/50 border border-white/10 rounded-lg p-6">
              <div className="flex items-start justify-between mb-2">
                <div className="flex-1">
                  <h3 className="text-xl font-semibold">{formatDate(session.date)}</h3>
                  <p className="text-sm text-gray-400">Oprettet af {session.createdByName}</p>
                </div>
              </div>
              {session.agenda && (
                <div className="mt-3 text-sm text-gray-300">
                  <span className="text-gray-400 font-semibold">Agenda:</span> {session.agenda}
                </div>
              )}
              {session.responses && session.responses.length > 0 ? (
                <div className="mt-4 pt-4 border-t border-white/10">
                  <h4 className="text-sm font-semibold text-gray-400 mb-2">
                    {session.responses.length} har svaret · {getAttendingCount(session.responses)} deltager
                  </h4>
                  <ul className="space-y-1.5">
                    {session.responses.map((r) => (
                      <li key={r.id} className="flex items-center justify-between text-sm">
                        <span className="text-gray-300">{r.displayName}</span>
                        <span className="px-2 py-0.5 rounded text-xs bg-neutral-800 text-gray-400">
                          {statusLabel(r.status)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <div className="mt-4 pt-4 border-t border-white/10">
                  <p className="text-sm text-gray-500">Ingen svar til denne session</p>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


