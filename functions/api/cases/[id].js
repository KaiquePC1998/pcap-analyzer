import { json } from '../../_lib/auth.js';

export async function onRequestDelete({ params, env, data }) {
  const id = Number(params.id);
  if (!id) return json({ error: 'id inválido.' }, 400);
  await env.DB.prepare('DELETE FROM cases WHERE id = ? AND user_id = ?').bind(id, data.user.id).run();
  return json({ ok: true });
}
