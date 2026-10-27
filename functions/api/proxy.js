// =============================================================================================
// Cloudflare Pages Function: /api/proxy?url=<URL codificada>
// ---------------------------------------------------------------------------------------------
// Proxy com cache compartilhado para as APIs de enriquecimento do PCAP Analyzer.
//
//  - Só aceita GET para hosts da allow list (não é um proxy aberto).
//  - Só aceita chamadas vindas do próprio site (Origin/Referer do mesmo host).
//  - Cache em duas camadas, compartilhado entre TODOS os usuários do site:
//      1. KV (binding API_CACHE, opcional): global e persistente, sobrevive a despejos da borda
//      2. Cache API da borda (caches.default): por datacenter, sem custo
//  - Chaves de API vêm de secrets do projeto (env.*), nunca do navegador. Se o secret não existir,
//    usa a chave enviada pelo navegador (compatível com a configuração local).
//  - ?fresh=1 ignora o cache na leitura (botões "reconsultar"/"testar"), mas grava a nova resposta.
// =============================================================================================

const HOUR = 3600;
const ALLOWED = {
  'ipwho.is':              { ttl: 7 * 24 * HOUR },
  'ipinfo.io':             { ttl: 7 * 24 * HOUR },
  'rdap.lacnic.net':       { ttl: 7 * 24 * HOUR, timeout: 8000 },
  'cloudflare-dns.com':    { ttl: 24 * HOUR },
  'pulsedive.com':         { ttl: 24 * HOUR },
  'api.abuseipdb.com':     { ttl: 24 * HOUR },
  'www.virustotal.com':    { ttl: 24 * HOUR },
  'observatory.manrs.org': { ttl: 3 * 24 * HOUR },
  'stat.ripe.net':         { ttl: 10 * 60, timeout: 18000 },   // bgp-state costuma levar vários segundos
};
const NEGATIVE_TTL = 15 * 60;              // respostas de erro/vazias: evita martelar a API
const SENSITIVE_PARAMS = ['key', 'apikey', 'api_key', 'token', 'access_token', 'auth', 'fresh'];
const DEFAULT_TIMEOUT = 5000;

function json(body, status = 200, extra = {}) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra },
  });
}

// Chave de cache sem credenciais: a mesma consulta com chaves diferentes compartilha o resultado
function cacheKeyOf(target) {
  const u = new URL(target.toString());
  SENSITIVE_PARAMS.forEach(p => u.searchParams.delete(p));
  u.searchParams.sort();
  return u.toString();
}

// Injeta credenciais SOMENTE de secrets do projeto (env.*). O navegador nunca mais manda chave.
function applyCredentials(target, headers, env) {
  const host = target.hostname;
  if (host === 'pulsedive.com') {
    if (env.PULSEDIVE_KEY) target.searchParams.set('key', env.PULSEDIVE_KEY);
  } else if (host === 'api.abuseipdb.com') {
    if (env.ABUSEIPDB_KEY) headers.set('Key', env.ABUSEIPDB_KEY);
  } else if (host === 'www.virustotal.com') {
    if (!target.pathname.startsWith('/api/v3/')) return;
    if (env.VIRUSTOTAL_KEY) headers.set('x-apikey', env.VIRUSTOTAL_KEY);
  } else if (host === 'observatory.manrs.org') {
    if (env.MANRS_KEY) headers.set('Authorization', `Bearer ${env.MANRS_KEY}`);
  }
}

// Aceita apenas chamadas do próprio site. Navegadores não enviam Origin em GET same-origin, então o
// front-end manda o cabeçalho X-PCAP-Client: outro site não consegue enviá-lo a partir do navegador
// sem um preflight CORS, que este endpoint nunca autoriza. Origin de outro host é sempre recusado.
function allowRequest(request) {
  const self = new URL(request.url).host;
  const origin = request.headers.get('Origin');
  try {
    if (origin && new URL(origin).host !== self) return false;
  } catch (e) {
    return false;
  }
  return request.headers.get('X-PCAP-Client') === '1';
}

export async function onRequestGet({ request, env, waitUntil }) {
  if (!allowRequest(request)) return json({ error: 'origin not allowed' }, 403);

  const params = new URL(request.url).searchParams;
  const raw = params.get('url');
  const fresh = params.get('fresh') === '1';
  let target;
  try {
    target = new URL(raw);
  } catch (e) {
    return json({ error: 'invalid url' }, 400);
  }
  const rule = ALLOWED[target.hostname];
  if (target.protocol !== 'https:' || !rule) return json({ error: 'host not allowed' }, 403);

  const key = cacheKeyOf(target);
  const edgeKey = new Request(`https://pcap-proxy-cache.internal/${encodeURIComponent(key)}`);
  const kv = env.API_CACHE || null;

  // 1. Leitura do cache (KV global -> borda)
  if (!fresh) {
    if (kv) {
      const hit = await kv.get(key);
      if (hit !== null) return json(hit, 200, { 'X-Cache': 'HIT-KV' });
    }
    const edgeHit = await caches.default.match(edgeKey);
    if (edgeHit) {
      const body = await edgeHit.text();
      const status = parseInt(edgeHit.headers.get('X-Upstream-Status') || '200', 10);
      return json(body, status, { 'X-Cache': 'HIT-EDGE' });
    }
  }

  // 2. Consulta à API de origem
  const headers = new Headers({ Accept: request.headers.get('Accept') || 'application/json' });
  applyCredentials(target, headers, env);
  const ctrl = new AbortController();
  const tid = setTimeout(() => ctrl.abort(), rule.timeout || DEFAULT_TIMEOUT);
  let upstream;
  try {
    upstream = await fetch(target.toString(), { headers, signal: ctrl.signal });
  } catch (e) {
    return json({ error: 'upstream unreachable' }, 504, { 'X-Cache': 'MISS' });
  } finally {
    clearTimeout(tid);
  }

  const body = await upstream.text();
  const ok = upstream.ok;
  const ttl = ok ? rule.ttl : NEGATIVE_TTL;
  const retryAfter = upstream.headers.get('Retry-After');

  // 3. Gravação: sucesso vai para KV + borda; erro só para a borda (curto), para não poluir o KV
  const edgeCopy = new Response(body, {
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': `public, max-age=${ttl}`,
      'X-Upstream-Status': String(upstream.status),
    },
  });
  waitUntil(caches.default.put(edgeKey, edgeCopy));
  if (ok && kv) waitUntil(kv.put(key, body, { expirationTtl: Math.max(ttl, 60) }));

  const extra = { 'X-Cache': 'MISS' };
  if (retryAfter) extra['Retry-After'] = retryAfter;
  return json(body, upstream.status, extra);
}
