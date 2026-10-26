import { json } from '../../_lib/auth.js';

// O middleware já validou a sessão e colocou o usuário em context.data.user
export async function onRequestGet({ data }) {
  return json({ user: data.user });
}
