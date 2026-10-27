// =============================================================================================
// Rate limiting baseado em D1 — usado no login (anti brute-force) e no envio de casos.
// Registra tentativas por (IP, e-mail) e por IP, e aplica janelas crescentes.
// =============================================================================================

const MINUTE = 60;

// Obtém o IP do cliente de forma segura: honra os cabeçalhos Cf-* quando presentes (proxied),
// senão usa o cabeçalho de conexão. Nunca confia em um X-Forwarded-For de origem arbitrária.
export function clientIp(request) {
  return (
    request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim()
    || '?'
  );
}

// Registra uma tentativa (sucesso ou falha) na tabela login_attempts.
export async function recordAttempt(db, ip, email) {
  await db.prepare('INSERT INTO login_attempts (ip, email, attempted_at) VALUES (?, ?, datetime(\'now\'))')
    .bind(ip, (email || '').toLowerCase()).run();
}

// Regista escrita de casos (contexto "cases-write" na mesma tabela).
export function recordCaseAttempt(db, ip, email) {
  return recordAttempt(db, ip, email || 'cases-write');
}

// Verifica se a tentativa atual deve ser bloqueada.
// Janelas: >30 falhas/15min por IP -> bloqueia 1h; >8 falhas/15min por (IP+email) -> bloqueia 5min.
export async function blocked(db, ip, email) {
  const since = `datetime('now', '-15 minutes')`;
  const byIp = await db.prepare(
    `SELECT COUNT(*) as n FROM login_attempts WHERE ip = ? AND attempted_at > ${since}`
  ).bind(ip).first();
  if (byIp.n >= 30) return { blocked: true, retryAfter: 3600, reason: 'Muitas tentativas. Tente novamente em 1 hora.' };

  const byPair = await db.prepare(
    `SELECT COUNT(*) as n FROM login_attempts WHERE ip = ? AND email = ? AND attempted_at > ${since}`
  ).bind(ip, (email || '').toLowerCase()).first();
  if (byPair.n >= 8) return { blocked: true, retryAfter: 300, reason: 'Muitas tentativas para esta conta. Tente novamente em 5 minutos.' };

  return { blocked: false };
}

// Limpa tentativas antigas para evitar que a tabela cresça sem limite.
export async function prune(db) {
  await db.prepare('DELETE FROM login_attempts WHERE attempted_at < datetime(\'now\', \'-24 hours\')').run();
}
