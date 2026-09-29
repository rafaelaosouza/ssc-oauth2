# google-oauth-express

Exemplo de autenticação com Google OAuth2 + autorização via RBAC (papéis "admin" e "user"), usando Express.

To install dependencies:

```bash
bun install
```

Configure as variáveis de ambiente no arquivo `process.env`:

```
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=http://localhost:3000/callback
ADMIN_EMAILS=seu-email@gmail.com   # e-mails com papel "admin" (separados por vírgula)
SESSION_SECRET=...                 # segredo aleatório para assinar a sessão
```

To run:

```bash
bun --env-file=process.env src/index.js
```

## Fluxo de RBAC

1. `/` inicia o login com o Google.
2. `/callback` valida o token do Google e grava na sessão do servidor o papel
   (`role`) do usuário: `admin` se o e-mail estiver em `ADMIN_EMAILS`, senão `user`.
3. `/welcome` mostra nome, e-mail e o papel atribuído.
4. `/admin` é uma rota protegida: só é liberada para quem tem papel `admin`
   (middleware `requireRole`); um usuário `user` recebe 403 e uma mensagem de
   acesso negado.

This project was created using `bun init` in bun v1.4.2. [Bun](https://bun.com) is a fast all-in-one JavaScript runtime.
