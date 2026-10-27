-- Schema de segurança, parte 2: controle de tentativas de login (anti brute-force).

CREATE TABLE IF NOT EXISTS login_attempts (
  ip          TEXT NOT NULL,              -- '::1', IP real ou "?" quando não houver XFF
  email       TEXT NOT NULL,              -- e-mail tentado (normalizado em minúsculas)
  attempted_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_login_att_ip   ON login_attempts(ip);
CREATE INDEX IF NOT EXISTS idx_login_att_email ON login_attempts(email);
