// =============================================================================================
// Middleware global do Cloudflare Pages: roda em TODA requisição (inclusive os arquivos estáticos).
// Exige sessão válida para qualquer página/rota, exceto a tela de login e o endpoint de login.
// =============================================================================================
import { getSessionUser, json } from './_lib/auth.js';

const PUBLIC_PATHS = new Set(['/login.html', '/login', '/api/auth/login', '/api/setup']);

// Headers de segurança adicionados a TODA resposta que o middleware emite (API/redirect).
// (Os arquivos estáticos/HTML já levam o CSP/HSTS do _headers.)
const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
};

function withSecurity(response) {
  const headers = new Headers(response.headers);
  Object.entries(SECURITY_HEADERS).forEach(([k, v]) => headers.set(k, v));
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  const isPublic = PUBLIC_PATHS.has(url.pathname)
    || url.pathname.startsWith('/_headers')
    || /\.(svg|png|ico|webmanifest)$/.test(url.pathname);
  if (isPublic) {
    // Serve normalmente, mas ainda aplica os headers de segurança também nas rotas públicas de API.
    if (url.pathname.startsWith('/api/')) return withSecurity(await next());
    return next();
  }

  if (!env.DB) {
    // Banco ainda não provisionado (ex.: preview local sem binding) — não derruba o site.
    return next();
  }

  const user = await getSessionUser(request, env.DB);

  if (url.pathname.startsWith('/api/')) {
    if (!user) return withSecurity(json({ error: 'Não autenticado.' }, 401));
    context.data = { user };
    return withSecurity(await next());
  }

  // Páginas normais: sem sessão, redireciona para o login
  if (!user) {
    return Response.redirect(new URL('/login', url.origin).toString(), 302);
  }
  context.data = { user };
  return withSecurity(await next());
}
