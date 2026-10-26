// =============================================================================================
// Helpers de autenticação compartilhados pelas Pages Functions (D1 + Web Crypto).
// Nunca importado como rota (prefixo "_"), só usado via import pelas demais functions.
// =============================================================================================

const PBKDF2_ITER = 100000;
const SESSION_DAYS = 7;
const COOKIE_NAME = 'pcap_session';

function toHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function randomHex(nBytes) {
  const bytes = new Uint8Array(nBytes);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

async function hashPassword(password, saltHex) {
  const salt = fromHex(saltHex);
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return toHex(bits);
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return toHex(digest);
}

// Cria o par (salt, hash) para gravar na tabela users
async function createPasswordRecord(password) {
  const password_salt = randomHex(16);
  const password_hash = await hashPassword(password, password_salt);
  return { password_salt, password_hash };
}

async function verifyPassword(password, saltHex, expectedHashHex) {
  const computed = await hashPassword(password, saltHex);
  if (computed.length !== expectedHashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) diff |= computed.charCodeAt(i) ^ expectedHashHex.charCodeAt(i);
  return diff === 0;
}

function parseCookies(request) {
  const header = request.headers.get('Cookie') || '';
  const out = {};
  header.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i === -1) return;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

function sessionCookieHeader(token, maxAgeSeconds) {
  const attrs = [
    `${COOKIE_NAME}=${token}`, 'Path=/', 'HttpOnly', 'Secure', 'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  return attrs.join('; ');
}

function clearSessionCookieHeader() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

async function createSession(db, userId) {
  const token = randomHex(32);
  const tokenHash = await sha256Hex(token);
  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 3600 * 1000).toISOString();
  await db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(tokenHash, userId, expires).run();
  return { token, maxAge: SESSION_DAYS * 24 * 3600 };
}

async function getSessionUser(request, db) {
  const cookies = parseCookies(request);
  const token = cookies[COOKIE_NAME];
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const row = await db.prepare(
    `SELECT u.id, u.email, u.name, u.role, u.active
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > datetime('now')`
  ).bind(tokenHash).first();
  if (!row || !row.active) return null;
  return row;
}

async function destroySession(request, db) {
  const cookies = parseCookies(request);
  const token = cookies[COOKIE_NAME];
  if (!token) return;
  const tokenHash = await sha256Hex(token);
  await db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
}

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders },
  });
}

export {
  createPasswordRecord, verifyPassword, createSession, getSessionUser, destroySession,
  clearSessionCookieHeader, sessionCookieHeader, json, randomHex,
};
