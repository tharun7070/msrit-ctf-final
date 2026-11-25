/**
 * CTFd REST API v1 client.
 *
 * All flag validation, scoring, and team membership are handled
 * exclusively by the CTFd backend. No secrets are stored here.
 *
 * Base URL is configured via VITE_CTFD_URL env variable (defaults to
 * same-origin so the Vite dev proxy / Nginx forward handles routing).
 */
import axios from 'axios';

const BASE = import.meta.env.VITE_CTFD_URL || '';

const api = axios.create({
  baseURL: BASE,
  withCredentials: true,          // send session cookies
  timeout: 3000,                  // 3 second timeout prevents UI hanging when backend is offline
  headers: { 'Content-Type': 'application/json' },
});

// CTFd 3.x CSRF nonce (fetched from /login or /settings HTML when needed)
let csrfNonce = null;

function extractNonce(html) {
  if (typeof html !== 'string') return null;
  const initMatch = html.match(/['"]csrfNonce['"]\s*:\s*['"]([^'"]+)['"]/);
  if (initMatch) return initMatch[1];
  const inputMatch = html.match(/name=["']nonce["'][^>]*value=["']([^"']+)["']/i)
    || html.match(/value=["']([^"']+)["'][^>]*name=["']nonce["']/i);
  return inputMatch ? inputMatch[1] : null;
}

async function ensureCsrf() {
  if (csrfNonce) return csrfNonce;
  const m = document.querySelector('meta[name="csrf-token"]');
  if (m) {
    csrfNonce = m.getAttribute('content');
    return csrfNonce;
  }
  const { data } = await api.get('/settings', { responseType: 'text' }).catch(() => ({ data: '' }));
  csrfNonce = extractNonce(data);
  return csrfNonce;
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();
  if (['post', 'put', 'patch', 'delete'].includes(method) && config.url?.startsWith('/api/')) {
    const nonce = await ensureCsrf();
    if (nonce) config.headers['CSRF-Token'] = nonce;
  }
  return config;
});

// ── Auth ───────────────────────────────────────────────────────────────
export async function login(name, password) {
  // CTFd 3.x authenticates via form POST /login with a CSRF nonce.
  const page = await api.get('/login', { responseType: 'text' });
  const nonce = extractNonce(page.data);
  if (!nonce) {
    throw new Error('Could not initialize login session. Please refresh and try again.');
  }

  const body = new URLSearchParams({ name, password, nonce, _submit: 'Submit' });
  const res = await api.post('/login?next=/settings', body.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  if (typeof res.data === 'string' && res.data.includes('Your username or password is incorrect')) {
    throw new Error('Invalid operative ID or access code.');
  }

  // Extract CSRF nonce from the redirected /settings page (or fetch /settings)
  csrfNonce = extractNonce(res.data);
  if (!csrfNonce) await ensureCsrf();
  return { success: true };
}

export async function register({ name, email, password }) {
  const { data } = await api.post('/api/v1/users', { name, email, password, type: 'user' });
  return data;
}

export async function logout() {
  csrfNonce = null;
  await api.get('/logout');
}

// ── Current user ───────────────────────────────────────────────────────
export async function getMe() {
  const { data } = await api.get('/api/v1/users/me');
  if (!data || typeof data !== 'object' || !data.data) {
    throw new Error('Not authenticated');
  }
  return data.data;
}

// ── Teams ──────────────────────────────────────────────────────────────
export async function getMyTeam() {
  const { data } = await api.get('/api/v1/teams/me');
  return data.data;
}

export async function createTeam(name, password) {
  const { data } = await api.post('/api/v1/teams', { name, password });
  return data.data;
}

export async function joinTeam(name, password) {
  const { data } = await api.post('/api/v1/teams/join', { name, password });
  return data;
}

export async function getTeamMembers(teamId) {
  const { data } = await api.get(`/api/v1/teams/${teamId}/members`);
  return data.data || [];
}

// ── Challenges ─────────────────────────────────────────────────────────
export async function getChallenges() {
  const { data } = await api.get('/api/v1/challenges');
  return data.data || [];
}

export async function getChallenge(id) {
  const { data } = await api.get(`/api/v1/challenges/${id}`);
  return data.data;
}

export async function getChallengeFiles(id) {
  const { data } = await api.get(`/api/v1/challenges/${id}/files`);
  return data.data || [];
}

export async function getChallengeHints(id) {
  const { data } = await api.get(`/api/v1/challenges/${id}/hints`);
  return data.data || [];
}

// ── Submissions ────────────────────────────────────────────────────────
/**
 * Submit a flag. Returns the full CTFd submission response.
 * Result will be 'correct', 'incorrect', 'already_solved', or similar.
 * Never stores the flag or the result in localStorage.
 */
export async function submitFlag(challengeId, submission) {
  const { data } = await api.post('/api/v1/challenges/attempt', {
    challenge_id: challengeId,
    submission,
  });
  return data;
}

// ── Solves / progress ──────────────────────────────────────────────────
export async function getMySolves() {
  const me = await getMe().catch(() => null);
  if (!me) return [];
  const { data } = await api.get(`/api/v1/users/${me.id}/solves`);
  return data.data || [];
}

export async function getTeamSolves(teamId) {
  const { data } = await api.get(`/api/v1/teams/${teamId}/solves`);
  return data.data || [];
}

// ── Scoreboard / leaderboard ───────────────────────────────────────────
export async function getScoreboard(count = 50) {
  const { data } = await api.get('/api/v1/scoreboard/top/' + count);
  return data.data || {};
}

export async function getStandings() {
  const { data } = await api.get('/api/v1/scoreboard');
  return data.data || [];
}

// ── Hints ──────────────────────────────────────────────────────────────
export async function unlockHint(hintId) {
  const { data } = await api.post('/api/v1/unlocks', { target: hintId, type: 'hints' });
  return data;
}

export async function getHintContent(hintId) {
  const { data } = await api.get(`/api/v1/hints/${hintId}`);
  return data.data;
}

// ── Event config ───────────────────────────────────────────────────────
export async function getConfig() {
  const { data } = await api.get('/api/v1/configs');
  return data.data || {};
}

export default api;
