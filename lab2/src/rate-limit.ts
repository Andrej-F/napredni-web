type AttemptState = {
  failedAttempts: number;
  blockedUntil: number | null;
};

const attempts = new Map<string, AttemptState>();
const MAX_FAILED_ATTEMPTS = 3;
const BLOCK_DURATION_MS = 5 * 60 * 1000;

function keyFor(ip: string, username: string): string {
  return `${ip}:${username}`;
}

export function getRateLimitState(ip: string, username: string): AttemptState {
  const key = keyFor(ip, username);
  const state = attempts.get(key);

  if (!state) {
    return { failedAttempts: 0, blockedUntil: null };
  }

  if (state.blockedUntil !== null && state.blockedUntil <= Date.now()) {
    attempts.delete(key);
    return { failedAttempts: 0, blockedUntil: null };
  }

  return state;
}

export function isBlocked(ip: string, username: string): boolean {
  return getRateLimitState(ip, username).blockedUntil !== null;
}

export function recordFailedAttempt(ip: string, username: string): AttemptState {
  const current = getRateLimitState(ip, username);
  const next: AttemptState = {
    failedAttempts: current.failedAttempts + 1,
    blockedUntil:
      current.failedAttempts + 1 >= MAX_FAILED_ATTEMPTS
        ? Date.now() + BLOCK_DURATION_MS
        : null,
  };
  attempts.set(keyFor(ip, username), next);
  return next;
}

export function clearAttempts(ip: string, username: string): void {
  attempts.delete(keyFor(ip, username));
}

export function secondsUntilUnblocked(ip: string, username: string): number {
  const blockedUntil = getRateLimitState(ip, username).blockedUntil;
  return blockedUntil === null ? 0 : Math.ceil((blockedUntil - Date.now()) / 1000);
}
