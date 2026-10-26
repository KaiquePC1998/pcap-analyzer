// Histórico de casos/análises — cada conta só vê e grava o próprio histórico.
import { json } from '../../_lib/auth.js';

export async function onRequestGet({ env, data }) {
  const { results } = await env.DB.prepare(
    'SELECT id, title, data, created_at FROM cases WHERE user_id = ? ORDER BY created_at DESC LIMIT 200'
  ).bind(data.user.id).all();
  return json({ cases: results.map(r => ({ id: r.id, title: r.title, created_at: r.created_at, ...JSON.parse(r.data) })) });
}

export async function onRequestPost({ request, env, data }) {
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido.' }, 400); }
  if (!body || typeof body !== 'object') return json({ error: 'Corpo inválido.' }, 400);

  const title = (body.title || body.currentFile || ('Caso ' + new Date().toLocaleString('pt-BR'))).slice(0, 200);
  const payload = JSON.stringify(body).slice(0, 500000); // limite de segurança por registro

  const result = await env.DB.prepare(
    'INSERT INTO cases (user_id, title, data) VALUES (?, ?, ?)'
  ).bind(data.user.id, title, payload).run();

  return json({ id: result.meta.last_row_id, title }, 201);
}
