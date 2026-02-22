import { useState, useEffect, useRef } from 'react';
import { collection, addDoc, doc, updateDoc, deleteDoc, onSnapshot, query, orderBy, Timestamp } from 'firebase/firestore';
import { db } from '@/firebase';
import { useAuth } from '@/hooks/useAuth';
import { TrainingSession, TrainingSessionResponse } from '@/types';
import { getFaceitName, isWhitelisted, TEAM_MEMBERS } from '@/utils/steamWhitelist';

type ResponseStatus = 'can_go_online' | 'can_go_hall' | 'cannot_go';

const EXPECTED_TEAM_SIZE = TEAM_MEMBERS.length;

function getAttendingCount(session: TrainingSession): number {
  return session.responses?.filter((r) => r.status !== 'cannot_go').length ?? 0;
}

const DAY_NAMES = ['Søndag', 'Mandag', 'Tirsdag', 'Onsdag', 'Torsdag', 'Fredag', 'Lørdag'];

export default function TrainingPage() {
  const { user } = useAuth();
  const [sessions, setSessions] = useState<TrainingSession[]>([]);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [createMode, setCreateMode] = useState<'single' | 'recurring'>('single');
  const [selectedDate, setSelectedDate] = useState('');
  const [recurringFrequency, setRecurringFrequency] = useState<'weekly' | 'monthly'>('weekly');
  const [recurringDayOfWeek, setRecurringDayOfWeek] = useState(3); // Wednesday = 3
  const [recurringStartDate, setRecurringStartDate] = useState('');
  const [recurringEndDate, setRecurringEndDate] = useState('');
  const [loading, setLoading] = useState(true);
  const [creatingRecurring, setCreatingRecurring] = useState(false);
  const [showAllUpcomingSessions, setShowAllUpcomingSessions] = useState(false);
  const [sessionToDelete, setSessionToDelete] = useState<TrainingSession | null>(null);
  const [sessionToViewResponses, setSessionToViewResponses] = useState<TrainingSession | null>(null);
  const [sessionToEditAgenda, setSessionToEditAgenda] = useState<TrainingSession | null>(null);
  const [agendaText, setAgendaText] = useState('');
  const migratedSessionIdsRef = useRef<Set<string>>(new Set());

  // Subscribe to training sessions
  useEffect(() => {
    const sessionsRef = collection(db, 'trainingSessions');
    const q = query(sessionsRef, orderBy('date', 'asc'));
    
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const sessionsData = snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data(),
      })) as TrainingSession[];
      
      setSessions(sessionsData);
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  /** First date on or after d that is the given day of week (0=Sun .. 6=Sat). */
  const snapToNextWeekday = (d: Date, dayOfWeek: number): Date => {
    const out = new Date(d);
    const diff = (dayOfWeek + 7 - out.getDay()) % 7;
    if (diff > 0) out.setDate(out.getDate() + diff);
    return out;
  };

  /** Last date on or before d that is the given day of week. */
  const snapToPrevWeekday = (d: Date, dayOfWeek: number): Date => {
    const out = new Date(d);
    const diff = (out.getDay() - dayOfWeek + 7) % 7;
    if (diff > 0) out.setDate(out.getDate() - diff);
    return out;
  };

  /** Same weekday in the next month (e.g. 2nd Wed → 2nd Wed next month). */
  const addMonthSameWeekday = (d: Date): Date => {
    const next = new Date(d.getFullYear(), d.getMonth() + 1, 1);
    const dayOfWeek = d.getDay();
    const occurrence = Math.ceil(d.getDate() / 7);
    let count = 0;
    for (let day = 1; day <= 31; day++) {
      next.setDate(day);
      if (next.getDay() === dayOfWeek) {
        count++;
        if (count === occurrence) return new Date(next);
      }
    }
    return new Date(next.getFullYear(), next.getMonth(), d.getDate());
  };

  /** Generate all recurring session dates between first and last (inclusive). Weekly = every 7 days; monthly = same weekday each month. */
  const getRecurringDates = (
    startStr: string,
    endStr: string,
    dayOfWeek: number,
    frequency: 'weekly' | 'monthly'
  ): string[] => {
    const start = new Date(startStr + 'T12:00:00');
    const end = new Date(endStr + 'T12:00:00');
    const first = snapToNextWeekday(start, dayOfWeek);
    const last = snapToPrevWeekday(end, dayOfWeek);
    if (first.getTime() > last.getTime()) return [];
    const dates: string[] = [];
    const d = new Date(first);
    while (d.getTime() <= last.getTime()) {
      dates.push(d.toISOString().slice(0, 10));
      if (frequency === 'weekly') {
        d.setDate(d.getDate() + 7);
      } else {
        const next = addMonthSameWeekday(d);
        d.setTime(next.getTime());
      }
    }
    return dates;
  };

  const handleCreateSession = async (e: React.FormEvent) => {
    e.preventDefault();

    if (createMode === 'single') {
      if (!selectedDate || !user) return;
      try {
        const faceitName = getFaceitName(user.steamId);
        await addDoc(collection(db, 'trainingSessions'), {
          date: selectedDate,
          createdBy: user.steamId,
          createdByName: faceitName,
          createdAt: Timestamp.now(),
          responses: [],
        });
        setSelectedDate('');
        setShowCreateForm(false);
      } catch (error) {
        console.error('Error creating training session:', error);
      }
      return;
    }

    // Recurring: generate all sessions between first and last (weekly or monthly on chosen day)
    if (!recurringStartDate || !recurringEndDate || !user) return;
    const dates = getRecurringDates(recurringStartDate, recurringEndDate, recurringDayOfWeek, recurringFrequency);
    if (dates.length === 0) return;
    setCreatingRecurring(true);
    try {
      const faceitName = getFaceitName(user.steamId);
      const col = collection(db, 'trainingSessions');
      for (const date of dates) {
        await addDoc(col, {
          date,
          createdBy: user.steamId,
          createdByName: faceitName,
          createdAt: Timestamp.now(),
          responses: [],
        });
      }
      setRecurringStartDate('');
      setRecurringEndDate('');
      setShowCreateForm(false);
    } catch (error) {
      console.error('Error creating recurring sessions:', error);
    } finally {
      setCreatingRecurring(false);
    }
  };

  const handleUpdateResponse = async (sessionId: string, status: ResponseStatus) => {
    if (!user) return;

    const session = sessions.find(s => s.id === sessionId);
    if (!session) return;

    const existingResponse = session.responses?.find(r => r.steamId === user.steamId);
    
    const faceitName = getFaceitName(user.steamId);
    const response: TrainingSessionResponse = {
      id: `response_${Date.now()}`,
      userId: user.steamId,
      steamId: user.steamId,
      displayName: faceitName,
      status,
      createdAt: new Date().toISOString(),
    };

    try {
      if (existingResponse) {
        // Update existing response
        const updatedResponses = session.responses.map(r => 
          r.steamId === user.steamId ? response : r
        );
        await updateDoc(doc(db, 'trainingSessions', sessionId), {
          responses: updatedResponses,
        });
      } else {
        // Add new response
        await updateDoc(doc(db, 'trainingSessions', sessionId), {
          responses: [...(session.responses || []), response],
        });
      }
    } catch (error) {
      console.error('Error updating response:', error);
    }
  };

  const getUserResponse = (session: TrainingSession): ResponseStatus | null => {
    if (!user) return null;
    const response = session.responses?.find(r => r.steamId === user.steamId);
    const status = response?.status;
    // Legacy: treat "can_go_both" as "can_go_hall" (option removed)
    if (status === 'can_go_both') return 'can_go_hall';
    return status || null;
  };

  // Migrate legacy "can_go_both" responses to "can_go_hall" in Firestore
  useEffect(() => {
    sessions.forEach(async (session) => {
      if (migratedSessionIdsRef.current.has(session.id)) return;
      const hasBoth = session.responses?.some((r) => r.status === 'can_go_both');
      if (!hasBoth) return;
      migratedSessionIdsRef.current.add(session.id);
      const migrated = session.responses!.map((r) =>
        r.status === 'can_go_both' ? { ...r, status: 'can_go_hall' as const } : r
      );
      try {
        await updateDoc(doc(db, 'trainingSessions', session.id), { responses: migrated });
      } catch (e) {
        console.error('Error migrating can_go_both to can_go_hall:', e);
      }
    });
  }, [sessions]);

  const canDeleteSession = (session: TrainingSession): boolean => {
    if (!user) return false;
    return session.createdBy === user.steamId || isWhitelisted(user.steamId);
  };

  const handleDeleteClick = (session: TrainingSession) => {
    setSessionToDelete(session);
  };

  const handleDeleteConfirm = async () => {
    if (!sessionToDelete) return;

    try {
      await deleteDoc(doc(db, 'trainingSessions', sessionToDelete.id));
      setSessionToDelete(null);
    } catch (error: unknown) {
      if (import.meta.env.DEV) {
        console.error('Error deleting training session:', error);
      }
      setSessionToDelete(null);
    }
  };

  const handleDeleteCancel = () => {
    setSessionToDelete(null);
  };

  const formatDateTime = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString('da-DK', { 
      year: 'numeric', 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const handleViewResponses = (session: TrainingSession) => {
    setSessionToViewResponses(session);
  };

  const handleEditAgenda = (session: TrainingSession) => {
    setSessionToEditAgenda(session);
    setAgendaText(session.agenda || '');
  };

  const handleSaveAgenda = async () => {
    if (!sessionToEditAgenda) return;

    try {
      await updateDoc(doc(db, 'trainingSessions', sessionToEditAgenda.id), {
        agenda: agendaText,
      });
      setSessionToEditAgenda(null);
      setAgendaText('');
    } catch (error) {
      console.error('Error saving agenda:', error);
    }
  };

  const truncateAgenda = (text: string | undefined) => {
    if (!text) return '';
    return text.length > 75 ? text.substring(0, 75) + '...' : text;
  };

  const isWednesday = (dateString: string) => {
    const date = new Date(dateString);
    return date.getDay() === 3; // Wednesday is day 3
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('da-DK', { 
      weekday: 'long', 
      year: 'numeric', 
      month: 'long', 
      day: 'numeric' 
    });
  };

  const getUpcomingSessions = (): TrainingSession[] => {
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    return sessions.filter((session) => {
      const sessionDate = new Date(session.date);
      sessionDate.setHours(0, 0, 0, 0);
      return sessionDate >= todayStart;
    });
  };

  const UPCOMING_PREVIEW_LIMIT = 3;
  const upcomingSessions = getUpcomingSessions();
  const upcomingSessionsToShow = showAllUpcomingSessions
    ? upcomingSessions
    : upcomingSessions.slice(0, UPCOMING_PREVIEW_LIMIT);
  const hasMoreUpcoming = upcomingSessions.length > UPCOMING_PREVIEW_LIMIT;

  const getNextTrainingDate = (): TrainingSession | null => {
    return upcomingSessions.length > 0 ? upcomingSessions[0] : null;
  };

  const nextSession = getNextTrainingDate();

  if (!user) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-400">Log ind for at se træningssessioner</p>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto">
      <div className="mb-8">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold mb-2">Træningssessioner</h1>
            <p className="text-gray-400">Opret og administrer holdets træningssessioner</p>
          </div>
        </div>
      </div>

      {/* Next Training Highlight */}
      {nextSession && (
        <div className="mb-8 bg-gradient-to-r from-blue-900/30 to-cyan-900/30 border border-blue-500/30 rounded-lg p-6">
          <h2 className="text-xl font-bold text-blue-300 mb-2">Næste træning</h2>
          <p className="text-2xl font-semibold mb-4">{formatDate(nextSession.date)}</p>
          
          <div className="flex gap-2 flex-wrap">
            <button
              onClick={() => handleUpdateResponse(nextSession.id, 'cannot_go')}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                getUserResponse(nextSession) === 'cannot_go'
                  ? 'bg-red-600 text-white'
                  : 'bg-neutral-800 text-gray-300 hover:bg-neutral-700'
              }`}
            >
              ❌ Kan ikke
            </button>
            <button
              onClick={() => handleUpdateResponse(nextSession.id, 'can_go_online')}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                getUserResponse(nextSession) === 'can_go_online'
                  ? 'bg-green-600 text-white'
                  : 'bg-neutral-800 text-gray-300 hover:bg-neutral-700'
              }`}
            >
              💻 Kan online
            </button>
            <button
              onClick={() => handleUpdateResponse(nextSession.id, 'can_go_hall')}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                getUserResponse(nextSession) === 'can_go_hall'
                  ? 'bg-green-600 text-white'
                  : 'bg-neutral-800 text-gray-300 hover:bg-neutral-700'
              }`}
            >
              🏢 Kan i forening
            </button>
          </div>

          {/* Agenda section */}
          {nextSession.agenda ? (
            <div className="mt-4 mb-4">
              <label className="text-sm font-semibold text-blue-400 mb-2 block">Agenda</label>
              <button
                onClick={() => handleEditAgenda(nextSession)}
                className="text-left w-full text-sm text-gray-300 hover:text-white transition-colors underline"
              >
                {truncateAgenda(nextSession.agenda)}
              </button>
            </div>
          ) : (
            <div className="mt-4 mb-4">
              <button
                onClick={() => handleEditAgenda(nextSession)}
                className="px-3 py-2 text-sm bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 border border-blue-500/30 rounded-md transition-colors"
              >
                + Tilføj agenda
              </button>
            </div>
          )}

          {/* Show response summary */}
          {nextSession.responses && nextSession.responses.length > 0 && (
            <div className="mt-6 pt-6 border-t border-white/10">
              <h3 className="text-sm font-semibold text-gray-400 uppercase mb-1">Svar</h3>
              <p className="text-sm text-gray-400 mb-3">
                {nextSession.responses.length} af {EXPECTED_TEAM_SIZE} har svaret · {getAttendingCount(nextSession)} deltager
              </p>
              {/* Desktop: Always show all responses */}
              <div className="hidden md:block space-y-2">
                {nextSession.responses.map((response) => (
                  <div key={response.id} className="flex items-center justify-between text-sm">
                    <div className="flex-1">
                      <span className="text-gray-300">{response.displayName}</span>
                      <span className="ml-2 text-xs text-gray-500">
                        {formatDateTime(response.createdAt)}
                      </span>
                    </div>
                    <span className={`px-2 py-1 rounded ${
                      response.status === 'cannot_go' ? 'bg-red-900/50 text-red-300' :
                      response.status === 'can_go_online' ? 'bg-blue-900/50 text-blue-300' :
                      'bg-green-900/50 text-green-300'
                    }`}>
                      {response.status === 'cannot_go' ? '❌ Kan ikke' :
                       response.status === 'can_go_online' ? '💻 Kan online' :
                       '🏢 Kan i forening'}
                    </span>
                  </div>
                ))}
              </div>
              {/* Mobile: Clickable summary */}
              <div className="md:hidden">
                <button
                  onClick={() => handleViewResponses(nextSession)}
                  className="text-sm text-gray-400 hover:text-white transition-colors underline"
                >
                  Se svar ({nextSession.responses.length} af {EXPECTED_TEAM_SIZE} har svaret · {getAttendingCount(nextSession)} deltager)
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Create New Session */}
      <div className="mb-8">
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 mb-4">
          <button
            onClick={() => setShowCreateForm(!showCreateForm)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-md font-medium transition-colors"
          >
            {showCreateForm ? 'Annuller' : 'Lav ny træningssession'}
          </button>
          <a
            href="/training/past"
            className="px-2 py-1 text-sm text-gray-400 hover:text-white hover:bg-white/5 border border-transparent rounded-md transition-colors"
          >
            Se tidligere træningssessions →
          </a>
        </div>

        {showCreateForm && (
          <form onSubmit={handleCreateSession} className="mt-4 bg-neutral-900/50 border border-white/10 rounded-lg p-6">
            <div className="flex gap-6 mb-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="createMode"
                  checked={createMode === 'single'}
                  onChange={() => setCreateMode('single')}
                  className="text-blue-600"
                />
                <span>Enkelt session</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="createMode"
                  checked={createMode === 'recurring'}
                  onChange={() => setCreateMode('recurring')}
                  className="text-blue-600"
                />
                <span>Gentagende</span>
              </label>
            </div>

            {createMode === 'single' && (
                <div className="mb-4">
                <label htmlFor="date" className="block text-sm font-semibold mb-2">
                  Træningsdato
                </label>
                <input
                  type="date"
                  id="date"
                  value={selectedDate}
                  onChange={(e) => setSelectedDate(e.target.value)}
                  className="w-full max-w-xs px-4 py-2 bg-neutral-800 border border-white/10 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required={createMode === 'single'}
                />
                {selectedDate && isWednesday(selectedDate) && (
                  <p className="mt-2 text-sm text-blue-400">✓ Dette er en onsdag (almindelig træningsdag)</p>
                )}
              </div>
            )}

            {createMode === 'recurring' && (
              <div className="mb-4 space-y-4">
                <div>
                  <span className="block text-sm font-semibold mb-2">Frekvens</span>
                  <div className="flex gap-6">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="recurringFrequency"
                        checked={recurringFrequency === 'weekly'}
                        onChange={() => setRecurringFrequency('weekly')}
                        className="text-blue-600"
                      />
                      <span>Ugentligt</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="recurringFrequency"
                        checked={recurringFrequency === 'monthly'}
                        onChange={() => setRecurringFrequency('monthly')}
                        className="text-blue-600"
                      />
                      <span>Månedligt</span>
                    </label>
                  </div>
                </div>
                <div>
                  <label htmlFor="recurring-day" className="block text-sm font-semibold mb-2">
                    Ugedag
                  </label>
                  <select
                    id="recurring-day"
                    value={recurringDayOfWeek}
                    onChange={(e) => setRecurringDayOfWeek(Number(e.target.value))}
                    className="w-full max-w-xs px-4 py-2 bg-neutral-800 border border-white/10 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    {DAY_NAMES.map((name, i) => (
                      <option key={i} value={i}>{name}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label htmlFor="recurring-start" className="block text-sm font-semibold mb-2">
                    Første {DAY_NAMES[recurringDayOfWeek].toLowerCase()}
                  </label>
                  <input
                    type="date"
                    id="recurring-start"
                    value={recurringStartDate}
                    onChange={(e) => setRecurringStartDate(e.target.value)}
                    className="w-full max-w-xs px-4 py-2 bg-neutral-800 border border-white/10 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required={createMode === 'recurring'}
                  />
                  <p className="mt-1 text-xs text-gray-500">Vælg en dato; vi bruger den første {DAY_NAMES[recurringDayOfWeek].toLowerCase()} på eller efter den.</p>
                </div>
                <div>
                  <label htmlFor="recurring-end" className="block text-sm font-semibold mb-2">
                    Sidste {DAY_NAMES[recurringDayOfWeek].toLowerCase()}
                  </label>
                  <input
                    type="date"
                    id="recurring-end"
                    value={recurringEndDate}
                    onChange={(e) => setRecurringEndDate(e.target.value)}
                    min={recurringStartDate || undefined}
                    className="w-full max-w-xs px-4 py-2 bg-neutral-800 border border-white/10 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required={createMode === 'recurring'}
                  />
                  <p className="mt-1 text-xs text-gray-500">Vælg en dato; vi bruger den sidste {DAY_NAMES[recurringDayOfWeek].toLowerCase()} på eller før den.</p>
                </div>
                {recurringStartDate && recurringEndDate && (
                  <p className="text-sm text-gray-400">
                    Opretter <strong>{getRecurringDates(recurringStartDate, recurringEndDate, recurringDayOfWeek, recurringFrequency).length}</strong> session
                    {getRecurringDates(recurringStartDate, recurringEndDate, recurringDayOfWeek, recurringFrequency).length !== 1 ? 'er' : ''}
                    {recurringFrequency === 'weekly'
                      ? ' — én hver uge mellem første og sidste dato.'
                      : ' — én om måneden (samme ugedag) fra første til sidste.'}
                  </p>
                )}
              </div>
            )}

            <button
              type="submit"
              disabled={creatingRecurring || (createMode === 'recurring' && (!recurringStartDate || !recurringEndDate))}
              className="px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-md font-medium transition-colors"
            >
              {creatingRecurring ? 'Opretter…' : createMode === 'single' ? 'Opret session' : 'Opret gentagende sessioner'}
            </button>
          </form>
        )}
      </div>

      {/* Upcoming Sessions List */}
      <div className="mb-8">
        <h2 className="text-2xl font-bold mb-4">Kommende sessioner</h2>
        {loading ? (
          <div className="text-center py-8 text-gray-400">Indlæser...</div>
        ) : upcomingSessions.length === 0 ? (
          <div className="text-center py-8 text-gray-400">Ingen kommende træningssessioner</div>
        ) : (
          <>
            <div className="space-y-4">
              {upcomingSessionsToShow.map((session) => {
              const userResponse = getUserResponse(session);
              return (
                <div 
                  key={session.id} 
                  className={`bg-neutral-900/50 border rounded-lg p-6 ${
                    isWednesday(session.date) 
                      ? 'border-blue-500/30 bg-blue-900/20' 
                      : 'border-white/10'
                  }`}
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <h3 className="text-xl font-semibold">
                        {formatDate(session.date)}
                        {isWednesday(session.date) && (
                          <span className="ml-2 text-sm text-blue-400">(Onsdag)</span>
                        )}
                      </h3>
                      <p className="text-sm text-gray-400">
                        Oprettet af {session.createdByName}
                      </p>
                    </div>
                    <div className="flex items-center gap-3">
                      {userResponse && (
                        <span className={`px-3 py-1 rounded text-sm font-medium ${
                          userResponse === 'cannot_go' ? 'bg-red-900/50 text-red-300' :
                          userResponse === 'can_go_online' ? 'bg-blue-900/50 text-blue-300' :
                          'bg-green-900/50 text-green-300'
                        }`}>
                          {userResponse === 'cannot_go' ? '❌ Kan ikke' :
                           userResponse === 'can_go_online' ? '💻 Kan online' :
                           '🏢 Kan i forening'}
                        </span>
                      )}
                      {canDeleteSession(session) && (
                        <button
                          onClick={() => handleDeleteClick(session)}
                          className="px-3 py-1 text-sm bg-red-600/20 hover:bg-red-600/40 text-red-400 border border-red-500/30 rounded-md transition-colors"
                          title="Slet session"
                        >
                          🗑️
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Agenda section */}
                  {session.agenda ? (
                    <div className="mb-4">
                      <label className="text-sm font-semibold text-gray-400 mb-2 block">Agenda</label>
                      <button
                        onClick={() => handleEditAgenda(session)}
                        className="text-left w-full text-sm text-gray-300 hover:text-white transition-colors underline"
                      >
                        {truncateAgenda(session.agenda)}
                      </button>
                    </div>
                  ) : (
                    <div className="mb-4">
                      <button
                        onClick={() => handleEditAgenda(session)}
                        className="px-3 py-2 text-sm bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 border border-blue-500/30 rounded-md transition-colors"
                      >
                        + Tilføj agenda
                      </button>
                    </div>
                  )}

                  <div className="flex gap-2 flex-wrap">
                    <button
                      onClick={() => handleUpdateResponse(session.id, 'cannot_go')}
                      className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                        userResponse === 'cannot_go'
                          ? 'bg-red-600 text-white'
                          : 'bg-neutral-800 text-gray-300 hover:bg-neutral-700'
                      }`}
                    >
                      ❌ Kan ikke
                    </button>
                    <button
                      onClick={() => handleUpdateResponse(session.id, 'can_go_online')}
                      className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                        userResponse === 'can_go_online'
                          ? 'bg-green-600 text-white'
                          : 'bg-neutral-800 text-gray-300 hover:bg-neutral-700'
                      }`}
                    >
                      💻 Kan online
                    </button>
                    <button
                      onClick={() => handleUpdateResponse(session.id, 'can_go_hall')}
                      className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                        userResponse === 'can_go_hall'
                          ? 'bg-green-600 text-white'
                          : 'bg-neutral-800 text-gray-300 hover:bg-neutral-700'
                      }`}
                    >
                      🏢 Kan i forening
                    </button>
                  </div>

                  {/* Response summary */}
                  {session.responses && session.responses.length > 0 && (
                    <div className="mt-4 pt-4 border-t border-white/10">
                      {/* Desktop: Always show all responses */}
                      <div className="hidden md:block space-y-2">
                        <p className="text-sm text-gray-400 mb-2">
                          {session.responses.length} af {EXPECTED_TEAM_SIZE} har svaret · {getAttendingCount(session)} deltager
                        </p>
                        {session.responses.map((response) => (
                          <div key={response.id} className="flex items-center justify-between text-sm">
                            <div className="flex-1">
                              <span className="text-gray-300">{response.displayName}</span>
                              <span className="ml-2 text-xs text-gray-500">
                                {formatDateTime(response.createdAt)}
                              </span>
                            </div>
                            <span className={`px-2 py-1 rounded ${
                              response.status === 'cannot_go' ? 'bg-red-900/50 text-red-300' :
                              response.status === 'can_go_online' ? 'bg-blue-900/50 text-blue-300' :
                              'bg-green-900/50 text-green-300'
                            }`}>
                              {response.status === 'cannot_go' ? '❌ Kan ikke' :
                               response.status === 'can_go_online' ? '💻 Kan online' :
                               '🏢 Kan i forening'}
                            </span>
                          </div>
                        ))}
                      </div>
                      {/* Mobile: Clickable summary */}
                      <div className="md:hidden">
                        <button
                          onClick={() => handleViewResponses(session)}
                          className="text-sm text-gray-400 hover:text-white transition-colors underline"
                        >
                          {session.responses.length} af {EXPECTED_TEAM_SIZE} har svaret · {getAttendingCount(session)} deltager
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
            </div>
            {hasMoreUpcoming && (
              <div className="mt-4 flex justify-center">
                <button
                  type="button"
                  onClick={() => setShowAllUpcomingSessions(!showAllUpcomingSessions)}
                  className="px-4 py-2 text-sm font-medium text-blue-400 hover:text-blue-300 bg-neutral-800 hover:bg-neutral-700 border border-white/10 rounded-md transition-colors"
                >
                  {showAllUpcomingSessions
                    ? 'Vis færre'
                    : `Se flere træningssessioner (${upcomingSessions.length - UPCOMING_PREVIEW_LIMIT} flere)`}
                </button>
              </div>
            )}
          </>
        )}
      </div>

      {/* View Responses Modal */}
      {sessionToViewResponses && (
        <div
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => setSessionToViewResponses(null)}
        >
          <div
            className="bg-neutral-900 border border-white/20 rounded-lg p-6 max-w-md w-full mx-4 max-h-[80vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold">Svar</h3>
              <button
                onClick={() => setSessionToViewResponses(null)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                ✕
              </button>
            </div>
            <p className="text-sm text-gray-400 mb-1">
              {formatDate(sessionToViewResponses.date)}
            </p>
            <p className="text-sm text-gray-400 mb-4">
              {sessionToViewResponses.responses.length} af {EXPECTED_TEAM_SIZE} har svaret · {getAttendingCount(sessionToViewResponses)} deltager
            </p>
            <div className="space-y-3">
              {sessionToViewResponses.responses.map((response) => (
                <div key={response.id} className="bg-neutral-800/50 rounded-lg p-3 border border-white/10">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-200 font-medium">{response.displayName}</span>
                    <span className={`px-2 py-1 rounded text-xs ${
                      response.status === 'cannot_go' ? 'bg-red-900/50 text-red-300' :
                      response.status === 'can_go_online' ? 'bg-blue-900/50 text-blue-300' :
                      'bg-green-900/50 text-green-300'
                    }`}>
                      {response.status === 'cannot_go' ? '❌ Kan ikke' :
                       response.status === 'can_go_online' ? '💻 Kan online' :
                       '🏢 Kan i forening'}
                    </span>
                  </div>
                  <p className="text-xs text-gray-400">
                    {formatDateTime(response.createdAt)}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {sessionToDelete && (
        <div
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => setSessionToDelete(null)}
        >
          <div
            className="bg-neutral-900 border border-white/20 rounded-lg p-6 max-w-md w-full mx-4"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-xl font-bold mb-4">Slet træningssession?</h3>
            <p className="text-gray-300 mb-6">
              Er du sikker på, at du vil slette træningssessionen den{' '}
              <span className="font-semibold">{formatDate(sessionToDelete.date)}</span>?
              Handlingen kan ikke fortrydes.
            </p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={handleDeleteCancel}
                className="px-4 py-2 bg-neutral-700 hover:bg-neutral-600 rounded-md font-medium transition-colors"
              >
                Annuller
              </button>
              <button
                onClick={handleDeleteConfirm}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-md font-medium transition-colors"
              >
                Slet
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Agenda Modal */}
      {sessionToEditAgenda && (
        <div
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => setSessionToEditAgenda(null)}
        >
          <div
            className="bg-neutral-900 border border-white/20 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold">Rediger agenda</h3>
              <button
                onClick={() => setSessionToEditAgenda(null)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                ✕
              </button>
            </div>
            <p className="text-sm text-gray-400 mb-4">
              {formatDate(sessionToEditAgenda.date)}
            </p>
            <textarea
              value={agendaText}
              onChange={(e) => setAgendaText(e.target.value)}
              className="flex-1 w-full px-4 py-3 bg-neutral-800 border border-white/10 rounded-md text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
              placeholder="Tilføj agenda for træningssessionen..."
              maxLength={20000}
            />
            <div className="flex items-center justify-between mt-4">
              <p className="text-xs text-gray-400">
                {agendaText.length} / 20.000 tegn
              </p>
              <div className="flex gap-3">
                <button
                  onClick={() => setSessionToEditAgenda(null)}
                  className="px-4 py-2 bg-neutral-700 hover:bg-neutral-600 rounded-md font-medium transition-colors"
                >
                  Annuller
                </button>
                <button
                  onClick={handleSaveAgenda}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-md font-medium transition-colors"
                >
                  Gem
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
