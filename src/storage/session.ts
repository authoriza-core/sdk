import type { Session, User } from '../types.js';

export const SESSION_VERSION = 1;

export const SESSION_KEY_PREFIX = 'authoriza:session:';

export type ParseStoredSessionResult = { ok: true; session: Session } | { ok: false };

/**
 * Parses and structurally validates a raw stored session. Returns
 * `{ ok: false }` for corrupt/incompatible data so the caller can discard it.
 */
export function parseStoredSession(raw: string): ParseStoredSessionResult {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return { ok: false };
  }
  if (!data || typeof data !== 'object') {
    return { ok: false };
  }
  const record = data as Record<string, unknown>;
  if (record.version !== SESSION_VERSION) {
    return { ok: false };
  }
  if (typeof record.accessToken !== 'string' || record.accessToken.length === 0) {
    return { ok: false };
  }
  if (record.refreshToken !== null && typeof record.refreshToken !== 'string') {
    return { ok: false };
  }
  if (typeof record.expiresAt !== 'number' || !Number.isFinite(record.expiresAt)) {
    return { ok: false };
  }

  let user: User | null = null;
  if (record.user !== null && record.user !== undefined) {
    if (typeof record.user !== 'object') {
      return { ok: false };
    }
    const userRecord = record.user as Record<string, unknown>;
    if (typeof userRecord.id !== 'string' || userRecord.id.length === 0) {
      return { ok: false };
    }
    user = { id: userRecord.id };
    if (typeof userRecord.email === 'string') {
      user.email = userRecord.email;
    }
    if (typeof userRecord.name === 'string') {
      user.name = userRecord.name;
    }
  }

  return {
    ok: true,
    session: {
      accessToken: record.accessToken,
      refreshToken: record.refreshToken,
      expiresAt: record.expiresAt,
      user,
    },
  };
}
