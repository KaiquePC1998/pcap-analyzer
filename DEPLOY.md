# Passo a passo — Autenticação + Banco de dados (Cloudflare D1)

> ✅ **Já provisionado em 2026-10-26** (você deu acesso full via token): banco D1
> `pcap-analyzer-db` com as tabelas `users`/`sessions`/`cases` criadas, projeto Pages
> **`pcap-analyzer` → https://pcap-analyzer-32a.pages.dev** publicado, binding `DB`
> conectado. **O que falta é só o Passo 7** (criar sua conta de admin).

Este guia ativa o controle de acesso e o histórico por conta no PCAP Analyzer.
Tudo roda no próprio Cloudflare (Pages Functions + D1), sem servidor externo.
Duração estimada: **15–25 minutos**.

---

## O que já foi criado no repositório

| Arquivo | Função |
|---|---|
| `functions/_middleware.js` | Trava o site inteiro: sem sessão válida → redireciona para `/login.html` |
| `functions/_lib/auth.js` | Senha (PBKDF2), sessão (cookie HttpOnly+Secure), helpers comuns |
| `functions/api/setup.js` | Cria a 1ª conta (admin) — só funciona enquanto a tabela estiver vazia |
| `functions/api/auth/login.js` | Login por e-mail/senha |
| `functions/api/auth/logout.js` | Encerra a sessão |
| `functions/api/auth/me.js` | Quem está logado (usado para "lembrar" a sessão) |
| `functions/api/admin/users.js` | Admin cadastra/ativa/desativa analistas (lista fechada) |
| `functions/api/cases/index.js` | Salvar/listar histórico de casos da conta logada |
| `functions/api/cases/[id].js` | Excluir caso do próprio histórico |
| `functions/api/proxy.js` | Proxy das APIs de enriquecimento (foi movido da raiz para cá) |
| `migrations/0001_init.sql` | Cria as tabelas `users`, `sessions`, `cases` |
| `wrangler.toml` | Config do banco D1 (falta só o `database_id`) |
| `login.html` | Tela de login / criação do admin no 1º acesso |

Comportamento de segurança: senha nunca viaja ou é armazenada em texto — só hash PBKDF2
(100 mil iterações) + salt por conta; o cookie de sessão é `HttpOnly` + `Secure`; cada
analista só enxerga o próprio histórico de casos.

---

## Pré-requisitos

1. **Node.js 20 ou mais novo** instalado no seu computador.
   Confira: abra o terminal e rode `node --version` (deve retornar `v20...` ou maior).
   Se não tiver, baixe em https://nodejs.org (versão LTS) e instale.
2. Ter **acesso à conta Cloudflare** onde o site `pcap-analyzer` está publicado
   (você precisa conseguir entrar no painel e ter permissão de deploy).
3. Saber **o nome do projeto Pages** do site (aparece no painel Cloudflare →
   Workers & Pages → `pcap-analyzer` ou parecido). Vamos chamá-lo de `<SEU_PAGES>`.

Abra o terminal (PowerShell ou Prompt de Comando) e siga do **Passo 1** adiante.
Rode um comando por vez e confira a saída antes de continuar.

---

## Passo 1 — Instalar a ferramenta de linha de comando (wrangler)

```bash
npm install -g wrangler
```

Confira a instalação:

```bash
wrangler --version
```

Se retornar um número (ex.: `3.x.x` ou `4.x.x`), está ok.
No Windows, se o comando não for encontrado depois de instalar, feche e reabra o terminal.

---

## Passo 2 — Conectar ao Cloudflare

```bash
wrangler login
```

O navegador abre pedindo autorização do Cloudflare — **aceite**. No terminal deve
aparecer `Successfully logged in`.

> Se o navegador não abrir, rode `wrangler login --browser false` e copie a URL gerada
> para um navegador manualmente.

Para conferir a conta conectada e o projeto Pages existente:

```bash
wrangler pages project list
```

Anote o **nome exato** do projeto (a resposta à pergunta 3 do pré-requisito).

---

## Passo 3 — Criar o banco de dados D1

```bash
wrangler d1 create pcap-analyzer-db
```

A saída será parecida com:

```
{
  "d1_databases": [
    {
      "database_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "database_name": "pcap-analyzer-db"
    }
  ]
}
```

Copie esse `database_id` (o UUID) — será usado no próximo passo.

---

## Passo 4 — Preencher o `wrangler.toml`

1. Abra o arquivo `wrangler.toml` (na pasta do projeto) no editor.
2. Na linha abaixo, substitua `<PREENCHER_APOS_CRIAR_O_BANCO>` pelo UUID do Passo 3:

```toml
[[d1_databases]]
binding = "DB"
database_name = "pcap-analyzer-db"
database_id = "COLE_AQUI_O_UUID_DO_PASSO_3"
```

3. Salve o arquivo.

Confira que ficou certo:

```bash
cat wrangler.toml
```

> Se você publica o site pelo **GitHub** (git integration), esse passo é apenas preparatório:
> o binding do painel será feito no **Passo 6A**. Se publica por **CLI**, o `wrangler.toml`
> já resolve tudo no **Passo 6B**.

---

## Passo 5 — Criar as tabelas no banco (migração)

### 5A. Uma vez, no banco remoto (produção):

```bash
wrangler d1 execute pcap-analyzer-db --remote --file=migrations/0001_init.sql
```

Saída esperada: `Executed 1 commands in N ms` (ou similar).

### 5B. Confira que as tabelas existem:

```bash
wrangler d1 execute pcap-analyzer-db --remote --command="SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
```

Deve listar as tabelas `cases`, `sessions` e `users`.

> Para testes locais (opcional) repita o comando sem `--remote` (usa o D1 local do seu
> computador). Isso é útil no Passo 8 para ensaiar o login sem publicar nada.

---

## Passo 6 — Conectar o banco ao site (escolha UM caminho)

### 6A. Se o site é publicado pelo GitHub (git integration)

As bindings de `wrangler.toml` **não** são usadas nesse modo — o binding é configurado
no painel:

1. Cloudflare Dashboard → **Workers & Pages** → seu projeto `<SEU_PAGES>`
2. Aba **Settings** → **Functions** → **D1 database bindings** → **Add binding**
   - Variable name: `DB`
   - D1 database: `pcap-analyzer-db`
3. **Save**. Repita em **Preview** (se quiser testar em ambiente de preview).
4. Faça o deploy: commite e faça o push no GitHub (a página é publicada sozinha) —
   veja o Passo 8 para rodar a migração antes, se ainda não rodou.

### 6B. Se o site é publicado por linha de comando (wrangler pages deploy)

O `wrangler.toml` já carrega o binding automaticamente:

```bash
cd C:/Users/kaiqu/Documents/pcap-analyzer
wrangler pages deploy . --project-name=<SEU_PAGES>
```

---

## Passo 7 — Primeiro acesso: criar a conta de administrador (você)

Depois que o deploy do Passo 6 estiver no ar:

1. Abra no navegador: `https://<SEU_PAGES>.pages.dev/login.html`
2. Como a tabela `users` está vazia, a tela mostra o formulário **"Criar conta de
   administrador"** — preencha com seu nome, seu e-mail e uma senha forte
   (mínimo 8 caracteres).
3. Clique em **Criar conta**.
4. Você entra logado como **admin**. O atalho de bootstrap se desativa sozinho
   (a partir de agora `login.html` só mostra o login normal).

> Se aparecer o formulário de login normal em vez do de criação, já existe um usuário
> cadastrado — confira com o comando do Passo 5B: `SELECT COUNT(*) FROM users;`

---

## Passo 8 — Cadastrar os analistas (lista fechada)

Logado como admin, dentro do app:

1. No **rodapé da barra lateral**, clique no **ícone de usuários** (abre a Gestão de contas).
2. Preencha: **nome**, **e-mail** e **senha** (mínimo 8 caracteres) do analista.
3. **Cadastrar**. Repita para cada pessoa do time.
4. O painel lista todos com a opção de **ativar/desativar** (desativado não consegue
   entrar; o histórico dele continua guardado se reativar depois).

Cada conta passa a ter **histórico próprio**: o botão "Salvar caso" grava no D1 e só o
dono do caso (ou o admin) vê.

---

## Passo 9 — Verificação final (checklist de aceite)

Com o site publicado e o banco conectado, confira que tudo funciona:

- [ ] Abrir `https://<SEU_PAGES>.pages.dev/` (raiz) **sem estar logado** → é redirecionado para `/login.html`
- [ ] Abrir `/login.html` diretamente → carrega a tela de login (ou de criação, se ainda não criou admin)
- [ ] Logar com a conta de admin → entra no app normalmente
- [ ] Logar com a conta de um analista → entra, mas o painel de usuários **não** aparece
- [ ] Salvar um caso com a conta A → fazer logout → logar com a conta B → o caso da A **não** aparece
- [ ] Badge de e-mail/nome no rodapé da sidebar mostra a conta logada
- [ ] Logout → voltar para a raiz → redireciona para o login de novo
- [ ] Consultas do proxy (ex.: RIPEstat, VirusTotal) continuam funcionando em `/api/proxy`

---

## Teste local (opcional, sem publicar nada)

Para ensaiar o fluxo completo no seu computador antes de ir para produção:

```bash
cd C:/Users/kaiqu/Documents/pcap-analyzer
wrangler d1 execute pcap-analyzer-db --local --file=migrations/0001_init.sql
wrangler pages dev . --d1 DB=pcap-analyzer-db
```

Abra `http://localhost:8788/login.html` e siga o mesmo fluxo do Passo 7 em diante
(o banco local fica em `.wrangler/` na pasta do projeto — pode apagar para "resetar").
> Se algum flag do wrangler for rejeitado nesta versão, rode `wrangler pages dev --help`
> para conferir a sintaxe atual.

---

## Problemas comuns

| Sintoma | Causa provável | Solução |
|---|---|---|
| Login mostra "Banco de dados não configurado" | Binding `DB` não conectado | Refaça o Passo 6 (painel ou CLI) e faça um novo deploy |
| O site abre sem pedir login (modo aberto) | O middleware detectou ausência do binding | É o comportamento seguro enquanto o `DB` não existe; conecte o binding que a trava entra |
| `login.html` mostra login normal em vez de "Criar administrador" | Já existe um usuário na tabela | Confira com o SELECT do Passo 5B; se foi você, é o esperado |
| Analista não consegue entrar | Conta desativada ou senha errada | Ative no painel de usuários (admin) ou recadastre |
| Analista esqueceu a senha | Sem reset na UI | Admin: desative e recadastre a conta (o histórico antigo fica na conta antiga). Para apagar definitivamente: `wrangler d1 execute pcap-analyzer-db --remote --command="DELETE FROM users WHERE id = N;"` — **destrutivo, apaga casos atrelados** |
| "Não autenticado" em `/api/...` | Cookie de sessão expirado (7 dias) | Faça logout e login novamente |
| Deploy pelo GitHub ignora o `wrangler.toml` | git integration não lê bindings do toml | Use o painel (Passo 6A) |

---

## Notas de segurança

- O cookie de sessão é `HttpOnly` + `Secure` + `SameSite=Lax` — o JavaScript do app
  nunca lê o token; só envia nas requisições.
- A senha é derivada com **PBKDF2-SHA256, 100 mil iterações, salt aleatório por conta**.
- O endpoint `POST /api/setup` (criação do admin) se auto-desativa após a 1ª conta.
- A lista é **fechada**: não existe autocadastro. Só o admin cria contas.
- Root de `/api/*` exige sessão válida; o `_middleware` também bloqueia o HTML estático.

---

*PCAP Analyzer · Deploy de autenticação — passos 1 a 9 nesta ordem.*
