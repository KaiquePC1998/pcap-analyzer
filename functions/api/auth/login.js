import { verifyPassword, createSession, sessionCookieHeader, json } from '../../_lib/auth.js';
import { clientIp, recordAttempt, blocked, prune } from '../../_lib/ratelimit.js';

export async function onRequestPost({ request, env, waitUntil }) {
  if (!env.DB) return json({ error: 'Banco de dados não configurado.' }, 500);

  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido.' }, 400); }
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  if (!email || !password) return json({ error: 'Informe e-mail e senha.' }, 400);

  // Abre para manter a janela 24h limpa (barato; roda junto com a tentativa).
  waitUntil(prune(env.DB));

  const ip = clientIp(request);
  const limit = await blocked(env.DB, ip, email);

  const user = await env.DB.prepare(
    'SELECT id, email, name, role, active, password_hash, password_salt FROM users WHERE email = ?'
  ).bind(email).first();

  const ok = user && user.active && await verifyPassword(password, user.password_salt, user.password_hash);

  if (!ok) {
    waitUntil(recordAttempt(env.DB, ip, email));
    if (limit.blocked) {
      return json({ error: limit.reason }, 429, { 'Retry-After': String(limit.retryAfter) });
    }
    return json({ error: 'Credenciais inválidas.' }, 401);
  }

  const { token, maxAge } = await createSession(env.DB, user.id);

  return json(
    { user: { id: user.id, email: user.email, name: user.name, role: user.role } },
    200,
    { 'Set-Cookie': sessionCookieHeader(token, maxAge) }
  );
}
