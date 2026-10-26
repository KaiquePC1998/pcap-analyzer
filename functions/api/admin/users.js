// Gestão da lista fechada de usuários — somente admin. O middleware já garante sessão válida.
import { createPasswordRecord, json } from '../../_lib/auth.js';

function requireAdmin(data) {
  return data.user && data.user.role === 'admin';
}

export async function onRequestGet({ env, data }) {
  if (!requireAdmin(data)) return json({ error: 'Apenas administradores.' }, 403);
  const { results } = await env.DB.prepare(
    'SELECT id, email, name, role, active, created_at FROM users ORDER BY created_at ASC'
  ).all();
  return json({ users: results });
}

export async function onRequestPost({ request, env, data }) {
  if (!requireAdmin(data)) return json({ error: 'Apenas administradores.' }, 403);

  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido.' }, 400); }
  const email = (body.email || '').trim().toLowerCase();
  const name = (body.name || '').trim();
  const password = body.password || '';
  const role = body.role === 'admin' ? 'admin' : 'analyst';
  if (!email || !name || password.length < 8) {
    return json({ error: 'Preencha nome, e-mail e uma senha com pelo menos 8 caracteres.' }, 400);
  }

  const exists = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (exists) return json({ error: 'Já existe uma conta com este e-mail.' }, 409);

  const { password_salt, password_hash } = await createPasswordRecord(password);
  const result = await env.DB.prepare(
    'INSERT INTO users (email, name, password_hash, password_salt, role) VALUES (?, ?, ?, ?, ?)'
  ).bind(email, name, password_hash, password_salt, role).run();

  return json({ user: { id: result.meta.last_row_id, email, name, role, active: 1 } }, 201);
}

// PATCH { id, active } — ativa/desativa um analista (admin não consegue se autodesativar)
export async function onRequestPatch({ request, env, data }) {
  if (!requireAdmin(data)) return json({ error: 'Apenas administradores.' }, 403);
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido.' }, 400); }
  const id = Number(body.id);
  const active = body.active ? 1 : 0;
  if (!id) return json({ error: 'id inválido.' }, 400);
  if (id === data.user.id && !active) return json({ error: 'Você não pode desativar sua própria conta.' }, 400);

  await env.DB.prepare('UPDATE users SET active = ? WHERE id = ?').bind(active, id).run();
  return json({ ok: true });
}
