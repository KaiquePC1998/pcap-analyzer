import { verifyPassword, createSession, sessionCookieHeader, json } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ error: 'Banco de dados não configurado.' }, 500);

  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido.' }, 400); }
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  if (!email || !password) return json({ error: 'Informe e-mail e senha.' }, 400);

  const user = await env.DB.prepare(
    'SELECT id, email, name, role, active, password_hash, password_salt FROM users WHERE email = ?'
  ).bind(email).first();

  if (!user || !user.active) return json({ error: 'Credenciais inválidas.' }, 401);

  const ok = await verifyPassword(password, user.password_salt, user.password_hash);
  if (!ok) return json({ error: 'Credenciais inválidas.' }, 401);

  const { token, maxAge } = await createSession(env.DB, user.id);

  return json(
    { user: { id: user.id, email: user.email, name: user.name, role: user.role } },
    200,
    { 'Set-Cookie': sessionCookieHeader(token, maxAge) }
  );
}
