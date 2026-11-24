/**
 * useChallenges — fetches and enriches CTFd challenges with FTA metadata.
 * Solve status is merged from actual CTFd backend data, never inferred locally.
 */
import { useState, useEffect, useCallback } from 'react';
import { getChallenges, getMySolves, getTeamSolves, getMyTeam } from '../services/ctfd';
import { getChallengeMeta, ALL_15_CHALLENGES } from '../data/challengeMeta';

export function useChallenges() {
  const [challenges, setChallenges] = useState(ALL_15_CHALLENGES);
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
          const level = meta.level || (c.value === 50 ? 'Easy' : c.value === 100 ? 'Medium' : 'Hard');
          const act = meta.act || (level === 'Easy' ? 'The Street Job' : level === 'Medium' ? 'The Big Heist' : 'The Final Getaway');
          return {
            ...meta,
            ...c,
            ctfd_id: c.id || idx + 1,
            id: c.id || idx + 1,
            fta_id: meta.fta_id || (c.name ? c.name.slice(0, 3) : `C${idx + 1}`),
            level,
            act,
            reward: meta.reward || c.value || (level === 'Easy' ? 50 : level === 'Medium' ? 100 : 160),
            location: meta.location || 'Los Santos Underground',
            files: meta.files || [],
            briefing: meta.briefing || c.description,
          };
        });
      } else {
        // Always provide all 20 authentic missions if CTFd is uninitialized or in preview
        enriched = ALL_15_CHALLENGES;
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
      // Fallback to the authentic 25 challenges
      setChallenges(ALL_15_CHALLENGES);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  return { challenges, solvedIds, loading, error, reload: load };
}
