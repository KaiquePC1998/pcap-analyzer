// =============================================================================================
// Bootstrap de uma única vez: cria a primeira conta (admin) quando a tabela users está vazia.
// Depois que existir ao menos um usuário, este endpoint se desativa sozinho (sempre 403).
// Uso: abrir /login.html pela primeira vez mostra o formulário "Criar conta de administrador"
// enquanto não houver nenhum usuário cadastrado.
// =============================================================================================
import { createPasswordRecord, createSession, sessionCookieHeader, json } from '../_lib/auth.js';

export async function onRequestGet({ env }) {
  if (!env.DB) return json({ error: 'Banco de dados não configurado.' }, 500);
  const row = await env.DB.prepare('SELECT COUNT(*) as n FROM users').first();
  return json({ needsSetup: row.n === 0 });
}

export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ error: 'Banco de dados não configurado.' }, 500);

  const row = await env.DB.prepare('SELECT COUNT(*) as n FROM users').first();
  if (row.n > 0) return json({ error: 'A conta de administrador já foi criada.' }, 403);

  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido.' }, 400); }
  const email = (body.email || '').trim().toLowerCase();
  const name = (body.name || '').trim();
  const password = body.password || '';
  if (!email || !name || password.length < 8) {
    return json({ error: 'Preencha nome, e-mail e uma senha com pelo menos 8 caracteres.' }, 400);
  }

  const { password_salt, password_hash } = await createPasswordRecord(password);
  const result = await env.DB.prepare(
    'INSERT INTO users (email, name, password_hash, password_salt, role) VALUES (?, ?, ?, ?, ?)'
  ).bind(email, name, password_hash, password_salt, 'admin').run();

  const userId = result.meta.last_row_id;
  const { token, maxAge } = await createSession(env.DB, userId);

  return json(
    { user: { id: userId, email, name, role: 'admin' } },
    200,
    { 'Set-Cookie': sessionCookieHeader(token, maxAge) }
  );
}
