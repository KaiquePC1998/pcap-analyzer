// Histórico de casos/análises — cada conta só vê e grava o próprio histórico.
import { json } from '../../_lib/auth.js';
import { clientIp, blocked, prune, recordCaseAttempt } from '../../_lib/ratelimit.js';
import { encrypt, decrypt, isEncrypted } from '../../_lib/crypto.js';

const MAX_CASES = 500;                    // teto por conta (Listar já limita a 200; aqui evita crescimento infinito)
const MAX_BYTES = 500000;                 // teto por registro (mesmo límite de antes, agora centralizado)

export async function onRequestGet({ env, data }) {
  const secret = env.ENCRYPTION_KEY;      // secret do projeto; se ausente, retorna em claro (retrocompatível)
  const { results } = await env.DB.prepare(
    'SELECT id, title, data, created_at FROM cases WHERE user_id = ? ORDER BY created_at DESC LIMIT 200'
  ).bind(data.user.id).all();
  const cases = await Promise.all(results.map(async r => {
    let raw = r.data;
    if (secret && isEncrypted(raw)) {
      try { raw = await decrypt(raw, secret); } catch { raw = null; }
    }
    if (raw === null) return { id: r.id, title: r.title, created_at: r.created_at, corrupted: true };
    try { return { id: r.id, title: r.title, created_at: r.created_at, ...JSON.parse(raw) }; }
    catch { return { id: r.id, title: r.title, created_at: r.created_at, corrupted: true }; }
  }));
  return json({ cases });
}

export async function onRequestPost({ request, env, data, waitUntil }) {
  if (!env.DB) return json({ error: 'Banco de dados não configurado.' }, 500);
  waitUntil(prune(env.DB));

  // Rate limit de escrita por IP (impede automação de encher o banco).
  const ip = clientIp(request);
  const lim = await blocked(env.DB, ip, 'cases-write');
  if (lim.blocked) return json({ error: lim.reason }, 429, { 'Retry-After': String(lim.retryAfter) });

  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'JSON inválido.' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return json({ error: 'Corpo inválido.' }, 400);

  const title = (body.title || body.currentFile || ('Caso ' + new Date().toLocaleString('pt-BR'))).slice(0, 200);
  const payload = JSON.stringify(body);
  if (payload.length > MAX_BYTES) {
    return json({ error: 'Caso excede o limite de 500 KB.' }, 413);
  }

  // Teto de casos por conta (anti crescimento infinito).
  const cnt = await env.DB.prepare('SELECT COUNT(*) as n FROM cases WHERE user_id = ?').bind(data.user.id).first();
  if (cnt.n >= MAX_CASES) {
    return json({ error: 'Limite de 500 casos por conta atingido.' }, 429);
  }

  // Criptografa o conteúdo em repouso se o secret do projeto estiver configurado.
  const stored = env.ENCRYPTION_KEY ? await encrypt(payload, env.ENCRYPTION_KEY) : payload;

  const result = await env.DB.prepare(
    'INSERT INTO cases (user_id, title, data) VALUES (?, ?, ?)'
  ).bind(data.user.id, title, stored).run();

  waitUntil(recordCaseAttempt(env.DB, ip));
  return json({ id: result.meta.last_row_id, title }, 201);
}
