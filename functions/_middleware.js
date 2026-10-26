// =============================================================================================
// Middleware global do Cloudflare Pages: roda em TODA requisição (inclusive os arquivos estáticos).
// Exige sessão válida para qualquer página/rota, exceto a tela de login e o endpoint de login.
// =============================================================================================
import { getSessionUser, json } from './_lib/auth.js';

const PUBLIC_PATHS = new Set(['/login.html', '/login', '/api/auth/login', '/api/setup']);

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  const isPublic = PUBLIC_PATHS.has(url.pathname)
    || url.pathname.startsWith('/_headers')
    || /\.(svg|png|ico|webmanifest)$/.test(url.pathname);
  if (isPublic) return next();

  if (!env.DB) {
    // Banco ainda não provisionado (ex.: preview local sem binding) — não derruba o site.
    return next();
  }

  const user = await getSessionUser(request, env.DB);

  if (url.pathname.startsWith('/api/')) {
    if (!user) return json({ error: 'Não autenticado.' }, 401);
    context.data = { user };
    return next();
  }

  // Páginas normais: sem sessão, redireciona para o login
  if (!user) {
    return Response.redirect(new URL('/login', url.origin).toString(), 302);
  }
  context.data = { user };
  return next();
}
