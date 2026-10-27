// =============================================================================================
// Criptografia em repouso (encryption at rest) para o conteúdo sensível dos casos.
// Padrão: AES-256-GCM autenticado (garantia de confidencialidade + integridade).
// O formato gravado no D1 é: <base64(iv)>.<base64(ciphertext+tag)> com o IV aleatório de 12 bytes.
// Fica apenas no servidor (env.ENCRYPTION_KEY como secret do projeto) — nunca chega ao navegador.
// =============================================================================================

function toBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function fromBase64(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Deriva uma chave de 256 bits a partir do secret (SHA-256 do secret de texto).
async function deriveKey(secret) {
  const raw = new TextEncoder().encode(secret);
  const digest = await crypto.subtle.digest('SHA-256', raw);
  return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// Encripta texto plano -> "iv.ciphertext" (ambos base64). AES-256-GCM com IV aleatório.
export async function encrypt(plaintext, secret) {
  const key = await deriveKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  return `${toBase64(iv)}.${toBase64(ct)}`;
}

// Decripta "iv.ciphertext" para texto plano. Lança erro se o secret estiver errado (tag não confere).
export async function decrypt(payload, secret) {
  const [ivB64, ctB64] = payload.split('.');
  if (!ivB64 || !ctB64) throw new Error('payload criptografado inválido');
  const key = await deriveKey(secret);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(ivB64) },
    key, fromBase64(ctB64)
  );
  return new TextDecoder().decode(plain);
}

// Detecta se um payload está no formato criptografado (começa com base64 + '.').
export function isEncrypted(payload) {
  return typeof payload === 'string' && payload.includes('.') && /^[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/.test(payload);
}
