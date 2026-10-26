import { destroySession, clearSessionCookieHeader, json } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  if (env.DB) await destroySession(request, env.DB);
  return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookieHeader() });
}
