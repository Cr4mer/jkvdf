// In-app onboarding, framework-agnostic. The UI renders what is defined here;
// nothing in this file touches the network.
//
// Everything happens inside the product, so nobody has to leave for a video:
// coach marks point at the real buttons, the first nade is made through the
// normal wizard with one explained decision per screen, and any help text can
// carry a short looping clip hosted on the platform itself.
//
// Layers:
//  1. First sign-in without a team: the create-or-join screen. Nothing else is reachable.
//  2. Empty book: the guided first-nade wizard, optionally pre-filled with EXAMPLE_NADE
//     so the user sees a finished nade before making their own.
//  3. Dashboard: a getting-started checklist derived from the team_onboarding view,
//     shown until every item is done or the user dismisses it.
//  Coach marks (TOUR_STEPS) attach to data-tour="<anchor>" attributes in the UI.

// ---------------------------------------------------------------- inputs

/** One row of the team_onboarding view (db/0002). */
export interface TeamOnboardingRow {
  team_id: string;
  member_count: number;
  nade_count: number;
  session_count: number;
  active_invite_count: number;
}

/** The two onboarding columns on profiles (db/0001). */
export interface ProfileOnboarding {
  tour_seen_at: string | null;
  checklist_dismissed_at: string | null;
}

/** A short clip or image hosted on the platform (an R2 key), shown inline next to help text. */
export interface HelpMedia {
  key: string;
  kind: 'video' | 'gif' | 'image';
  alt: string;
}

export interface Help {
  text: string;
  media?: HelpMedia;
}

export interface Option {
  value: string;
  label: string;
  hint?: string;
}

// ---------------------------------------------------------------- 1. first run

export type FirstRunScreen = 'create_or_join_team' | 'guided_first_nade' | 'dashboard';

/** Where a signed-in user lands. `team` is null when they belong to no team yet. */
export function firstRunScreen(team: TeamOnboardingRow | null): FirstRunScreen {
  if (!team) return 'create_or_join_team';
  if (team.nade_count === 0) return 'guided_first_nade';
  return 'dashboard';
}

export const CREATE_OR_JOIN = {
  title: 'Your team\'s nade book',
  body: 'Nades belong to a team and only the team sees them. Create a team, or paste the invite link a teammate sent you.',
  create: { label: 'Create a team', route: '/team/new' },
  join: { label: 'I have an invite link', route: '/join' },
} as const;

// ---------------------------------------------------------------- 2. guided first nade

export const MAPS: readonly Option[] = [
  { value: 'de_mirage', label: 'Mirage' },
  { value: 'de_inferno', label: 'Inferno' },
  { value: 'de_nuke', label: 'Nuke' },
  { value: 'de_ancient', label: 'Ancient' },
  { value: 'de_anubis', label: 'Anubis' },
  { value: 'de_dust2', label: 'Dust II' },
  { value: 'de_train', label: 'Train' },
  { value: 'de_overpass', label: 'Overpass' },
  { value: 'de_vertigo', label: 'Vertigo' },
];

export const GRENADES: readonly Option[] = [
  { value: 'smoke', label: 'Smoke', hint: 'Blocks a line of sight for about 18 seconds.' },
  { value: 'flash', label: 'Flash', hint: 'Blinds anyone looking at it. Pop flashes for entries.' },
  { value: 'molotov', label: 'Molotov / Incendiary', hint: 'Clears a spot or delays a push.' },
  { value: 'he', label: 'HE grenade', hint: 'Damage on a common position.' },
  { value: 'decoy', label: 'Decoy', hint: 'Fake presence or footsteps.' },
];

export const SIDES: readonly Option[] = [
  { value: 't', label: 'T side' },
  { value: 'ct', label: 'CT side' },
  { value: 'both', label: 'Both sides' },
];

export const THROWS: readonly Option[] = [
  { value: 'stand', label: 'Standing throw', hint: 'Stand still and left click.' },
  { value: 'crouch', label: 'Crouched throw', hint: 'Hold crouch, then left click.' },
  { value: 'jump', label: 'Jump throw', hint: 'Jump and release at the top. A jumpthrow bind keeps it consistent.' },
  { value: 'walk_jump', label: 'Walk + jump throw', hint: 'Hold W or shift-walk, jump, release.' },
  { value: 'run_jump', label: 'Run + jump throw', hint: 'Sprint forward, jump, release.' },
  { value: 'other', label: 'Other', hint: 'Describe it in the notes.' },
];

export interface RadarPoint {
  /** 0..1 across the radar image, left to right */
  x: number;
  /** 0..1 down the radar image, top to bottom */
  y: number;
}

/** What the wizard collects. Field names match the nades table. */
export interface NadeDraft {
  map?: string;
  type?: string;
  side?: string;
  throw?: string;
  from_pos?: RadarPoint;
  to_pos?: RadarPoint;
  title?: string;
  description?: string;
  setpos?: string;
  /** A clip, or null when the user chose to skip the step. */
  video?: { bytes: number; seconds: number } | null;
}

export type WizardStepId = 'map' | 'grenade' | 'throw' | 'positions' | 'details' | 'video';

export interface WizardStep {
  id: WizardStepId;
  title: string;
  /** The one decision this screen asks for. */
  question: string;
  help: Help;
  optional?: boolean;
  isComplete(draft: NadeDraft): boolean;
}

const MAP_RE = /^[a-z0-9_]{3,40}$/;
const isPoint = (p: RadarPoint | undefined): boolean =>
  !!p && p.x >= 0 && p.x <= 1 && p.y >= 0 && p.y <= 1;
const oneOf = (options: readonly Option[], v: string | undefined): boolean =>
  v !== undefined && options.some((o) => o.value === v);

export const NADE_WIZARD: readonly WizardStep[] = [
  {
    id: 'map',
    title: 'Map',
    question: 'Which map is this lineup for?',
    help: { text: 'Your book is organised by map. Pick one now; you can filter by it later.' },
    isComplete: (d) => d.map !== undefined && MAP_RE.test(d.map),
  },
  {
    id: 'grenade',
    title: 'Grenade and side',
    question: 'Which grenade, and for which side?',
    help: { text: 'Choose both sides only for lineups that work from the same spot in both halves.' },
    isComplete: (d) => oneOf(GRENADES, d.type) && oneOf(SIDES, d.side),
  },
  {
    id: 'throw',
    title: 'Throw',
    question: 'How is it thrown?',
    help: {
      text: 'The throw type decides whether a teammate can reproduce it. When unsure, watch the clip you are about to record.',
      media: { key: 'help/throw-types.mp4', kind: 'video', alt: 'The five throw types shown side by side' },
    },
    isComplete: (d) => oneOf(THROWS, d.throw),
  },
  {
    id: 'positions',
    title: 'Positions',
    question: 'Where do you stand, and where does it land?',
    help: {
      text: 'Click the radar where you stand to throw, then where the grenade lands. Drag either pin to adjust.',
      media: { key: 'help/radar-two-clicks.mp4', kind: 'video', alt: 'Two clicks on the radar placing the throw and landing pins' },
    },
    isComplete: (d) => isPoint(d.from_pos) && isPoint(d.to_pos),
  },
  {
    id: 'details',
    title: 'Name',
    question: 'What is it called, and when do you use it?',
    help: {
      text: 'A short name teammates will recognise in a call, for example "A site smoke from T spawn". '
          + 'Optional: open the console in CS2, type getpos, and paste the result. Teammates can then teleport to the exact spot when practising.',
      media: { key: 'help/getpos.mp4', kind: 'video', alt: 'Typing getpos in the CS2 console and copying the result' },
    },
    isComplete: (d) => (d.title ?? '').trim().length >= 1 && (d.title ?? '').length <= 80,
  },
  {
    id: 'video',
    title: 'Clip',
    question: 'Add a clip of the throw?',
    help: {
      text: 'Optional, up to 30 seconds and 50 MB. Show the lineup on screen, the throw, and where it lands. You can add it later.',
      media: { key: 'help/record-clip.mp4', kind: 'video', alt: 'Recording a short clip of a lineup' },
    },
    optional: true,
    isComplete: (d) => d.video !== undefined,   // a clip, or an explicit skip (null)
  },
];

/** The first required step that is not done, or null when the draft can be saved. */
export function nextIncompleteStep(draft: NadeDraft): WizardStepId | null {
  const step = NADE_WIZARD.find((s) => !s.optional && !s.isComplete(draft));
  return step ? step.id : null;
}

export function wizardProgress(draft: NadeDraft): { completed: number; total: number } {
  return {
    completed: NADE_WIZARD.filter((s) => s.isComplete(draft)).length,
    total: NADE_WIZARD.length,
  };
}

/** Limits come from the plan row (plans.max_video_bytes, plans.max_video_seconds). */
export function videoWithinLimits(
  video: { bytes: number; seconds: number },
  limits: { max_video_bytes: number; max_video_seconds: number },
): { ok: true } | { ok: false; reason: 'too_large' | 'too_long' } {
  if (video.bytes > limits.max_video_bytes) return { ok: false, reason: 'too_large' };
  if (video.seconds > limits.max_video_seconds) return { ok: false, reason: 'too_long' };
  return { ok: true };
}

/**
 * Pre-filled example for the guided first nade. The decisions are made; the
 * positions are deliberately left empty so the user's first interaction is the
 * two clicks on the radar. They can save it as their first nade or start over.
 */
export const EXAMPLE_NADE: NadeDraft = {
  map: 'de_mirage',
  type: 'smoke',
  side: 't',
  throw: 'jump',
  title: 'Example: A site smoke from T spawn',
  description: 'Replace this with your own lineup. Smokes like this one let the team cross into A without being seen from the site.',
};

export const GUIDED_INTRO = {
  title: 'Add your first nade',
  body: 'Six small decisions and two clicks on the radar. We have filled in an example; change anything, or clear it and start with your own.',
  useExample: { label: 'Start from the example' },
  startBlank: { label: 'Start blank' },
} as const;

// ---------------------------------------------------------------- 3. checklist

export type ChecklistId = 'create_team' | 'first_nade' | 'first_map' | 'invite' | 'first_session';

export interface ChecklistItem {
  id: ChecklistId;
  title: string;
  detail: string;
  done: boolean;
  route: string;
}

/** Nades on one map before a team can run a full practice from the book. */
export const FIRST_MAP_TARGET = 10;

export function checklist(team: TeamOnboardingRow): ChecklistItem[] {
  const waitingOnInvite = team.member_count < 2 && team.active_invite_count > 0;
  return [
    {
      id: 'create_team',
      title: 'Create your team',
      detail: 'Done. This book is private to your team.',
      done: true,
      route: '/team',
    },
    {
      id: 'first_nade',
      title: 'Add your first nade',
      detail: 'Map, grenade, throw, two clicks on the radar, a name.',
      done: team.nade_count >= 1,
      route: '/nades/new',
    },
    {
      id: 'first_map',
      title: `Cover one map with ${FIRST_MAP_TARGET} nades`,
      detail: 'Enough to run a full practice from the book.',
      done: team.nade_count >= FIRST_MAP_TARGET,
      route: '/nades/new',
    },
    {
      id: 'invite',
      title: 'Invite a teammate',
      detail: waitingOnInvite
        ? 'Link created. It is done when someone joins.'
        : 'Anyone with the link joins as a member and can add nades too.',
      done: team.member_count >= 2,
      route: '/team/invite',
    },
    {
      id: 'first_session',
      title: 'Schedule your first practice',
      detail: 'Pick a time. Teammates get to RSVP.',
      done: team.session_count >= 1,
      route: '/schedule/new',
    },
  ];
}

export function showChecklist(team: TeamOnboardingRow, profile: ProfileOnboarding): boolean {
  if (profile.checklist_dismissed_at) return false;
  return checklist(team).some((item) => !item.done);
}

// ---------------------------------------------------------------- coach marks

export interface TourStep {
  /** Matches data-tour="<anchor>" on the element to highlight. */
  anchor: string;
  title: string;
  body: string;
}

export const TOUR_STEPS: readonly TourStep[] = [
  {
    anchor: 'nav-nades',
    title: 'Your nade book',
    body: 'Every lineup your team saves lives here, filtered by map, grenade and side.',
  },
  {
    anchor: 'add-nade',
    title: 'Add a nade',
    body: 'Six decisions: map, grenade and side, throw, where you stand and where it lands, a name, and an optional clip.',
  },
  {
    anchor: 'usage-meter',
    title: 'Your free slots',
    body: 'The Free plan holds 30 nades per team. Delete one to free a slot, or upgrade for unlimited.',
  },
  {
    anchor: 'nav-schedule',
    title: 'Practice schedule',
    body: 'Plan sessions and see who is coming.',
  },
  {
    anchor: 'invite',
    title: 'Bring the team',
    body: 'Copy an invite link. Anyone who opens it joins as a member.',
  },
];

/** Show once. The UI sets profiles.tour_seen_at when the tour ends or is skipped. */
export function shouldShowTour(profile: ProfileOnboarding): boolean {
  return profile.tour_seen_at === null;
}
