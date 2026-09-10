import test from 'node:test';
import assert from 'node:assert/strict';
import {
  checklist, EXAMPLE_NADE, firstRunScreen, NADE_WIZARD, nextIncompleteStep, shouldShowTour,
  showChecklist, TOUR_STEPS, videoWithinLimits, wizardProgress,
  type NadeDraft, type TeamOnboardingRow,
} from '../onboarding/onboarding.ts';

const fresh: TeamOnboardingRow = { team_id: 't', member_count: 1, nade_count: 0, session_count: 0, active_invite_count: 0 };
const done: TeamOnboardingRow = { team_id: 't', member_count: 5, nade_count: 12, session_count: 1, active_invite_count: 0 };

test('first run: no team, then guided first nade, then dashboard', () => {
  assert.equal(firstRunScreen(null), 'create_or_join_team');
  assert.equal(firstRunScreen(fresh), 'guided_first_nade');
  assert.equal(firstRunScreen({ ...fresh, nade_count: 1 }), 'dashboard');
});

test('wizard: the example leaves only the radar clicks, then the details are already there', () => {
  assert.equal(nextIncompleteStep({}), 'map');
  assert.equal(nextIncompleteStep(EXAMPLE_NADE), 'positions');

  const placed: NadeDraft = { ...EXAMPLE_NADE, from_pos: { x: 0.2, y: 0.7 }, to_pos: { x: 0.55, y: 0.3 } };
  assert.equal(nextIncompleteStep(placed), null);                 // clip is optional
  assert.deepEqual(wizardProgress(placed), { completed: 5, total: 6 });
  assert.deepEqual(wizardProgress({ ...placed, video: null }), { completed: 6, total: 6 });

  assert.equal(nextIncompleteStep({ ...placed, title: '   ' }), 'details');
  assert.equal(nextIncompleteStep({ ...placed, from_pos: { x: 1.2, y: 0.5 } }), 'positions');
  assert.equal(nextIncompleteStep({ ...placed, throw: 'backflip' }), 'throw');
  assert.equal(nextIncompleteStep({ ...placed, map: 'Mirage' }), 'map');   // must match the DB check
});

test('wizard: every step asks one question and has help; ids are unique', () => {
  const ids = NADE_WIZARD.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const s of NADE_WIZARD) {
    assert.ok(s.question.endsWith('?'), `${s.id} should ask a question`);
    assert.ok(s.help.text.length > 20, `${s.id} needs help text`);
  }
});

test('video limits come from the plan row', () => {
  const limits = { max_video_bytes: 52428800, max_video_seconds: 30 };
  assert.deepEqual(videoWithinLimits({ bytes: 10_000_000, seconds: 12 }, limits), { ok: true });
  assert.deepEqual(videoWithinLimits({ bytes: 60_000_000, seconds: 12 }, limits), { ok: false, reason: 'too_large' });
  assert.deepEqual(videoWithinLimits({ bytes: 10_000_000, seconds: 31 }, limits), { ok: false, reason: 'too_long' });
});

test('checklist: derived from counts, hidden when dismissed or complete', () => {
  const items = checklist(fresh);
  assert.deepEqual(items.map((i) => [i.id, i.done]), [
    ['create_team', true], ['first_nade', false], ['first_map', false], ['invite', false], ['first_session', false],
  ]);
  assert.match(checklist({ ...fresh, active_invite_count: 1 })[3].detail, /Link created/);
  assert.equal(showChecklist(fresh, { tour_seen_at: null, checklist_dismissed_at: null }), true);
  assert.equal(showChecklist(fresh, { tour_seen_at: null, checklist_dismissed_at: '2026-09-10T00:00:00Z' }), false);
  assert.ok(checklist(done).every((i) => i.done));
  assert.equal(showChecklist(done, { tour_seen_at: null, checklist_dismissed_at: null }), false);
});

test('tour: shown once, anchors unique', () => {
  assert.equal(shouldShowTour({ tour_seen_at: null, checklist_dismissed_at: null }), true);
  assert.equal(shouldShowTour({ tour_seen_at: '2026-09-10T00:00:00Z', checklist_dismissed_at: null }), false);
  const anchors = TOUR_STEPS.map((s) => s.anchor);
  assert.equal(new Set(anchors).size, anchors.length);
});
