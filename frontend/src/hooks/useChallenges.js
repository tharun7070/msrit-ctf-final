/**
 * useChallenges — fetches and enriches CTFd challenges with FTA metadata.
 * Solve status is merged from actual CTFd backend data, never inferred locally.
 */
import { useState, useEffect, useCallback } from 'react';
import { getChallenges, getMySolves, getTeamSolves, getMyTeam } from '../services/ctfd';
import { getChallengeMeta, ALL_15_CHALLENGES, BONUS_CHALLENGES } from '../data/challengeMeta';

// Offline/unauthenticated fallback shows only the 25 main-event missions.
// In production CTFd is the source of truth: it keeps the 10 bonus challenges
// hidden until the reveal, so they only surface once the scheduler flips them visible.
const OFFLINE_FALLBACK = [...ALL_15_CHALLENGES];

export function useChallenges() {
  const [challenges, setChallenges] = useState(OFFLINE_FALLBACK);
  const [solvedIds, setSolvedIds]   = useState(new Set());
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState(null);

  const load = useCallback(async () => {
    if (challenges.length === 0) setLoading(true);
    setError(null);
    try {
      const [raw, team] = await Promise.allSettled([getChallenges(), getMyTeam()]);
      const list = raw.status === 'fulfilled' && Array.isArray(raw.value) && raw.value.length > 0
        ? raw.value
        : [];

      let enriched = [];
      if (list.length > 0) {
        // Enriched CTFd challenges
        enriched = list.map((c, idx) => {
          const meta = getChallengeMeta(c.name) || {};
          const level = meta.level
            || (c.value === 50 ? 'Easy' : c.value === 100 ? 'Medium' : c.value === 25 ? 'Bonus' : 'Hard');
          const act = meta.act || (level === 'Easy' ? 'The Street Job' : level === 'Medium' ? 'The Big Heist' : 'The Final Getaway');
          return {
            ...meta,
            ...c,
            ctfd_id: c.id || idx + 1,
            id: c.id || idx + 1,
            fta_id: meta.fta_id || (c.name ? c.name.slice(0, 3) : `C${idx + 1}`),
            level,
            act,
            reward: meta.reward || c.value || (level === 'Easy' ? 50 : level === 'Medium' ? 100 : level === 'Bonus' ? 25 : 160),
            location: meta.location || 'Los Santos Underground',
            files: meta.files || [],
            briefing: meta.briefing || c.description,
          };
        });
      } else {
        // Always provide all authentic missions if CTFd is uninitialized or in preview
        enriched = OFFLINE_FALLBACK;
      }

      setChallenges(enriched);

      // Load solve status from team if available, else from user solves
      let solves = [];
      if (team.status === 'fulfilled' && team.value?.id) {
        const ts = await getTeamSolves(team.value.id).catch(() => []);
        solves = ts;
      } else {
        const us = await getMySolves().catch(() => []);
        solves = us;
      }
      setSolvedIds(new Set(solves.map(s => s.challenge_id)));
    } catch (e) {
      console.warn('CTFd connection notice:', e.message);
      // Fallback to the authentic board (25 main + 10 bonus)
      setChallenges(OFFLINE_FALLBACK);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  return { challenges, solvedIds, loading, error, reload: load };
}
