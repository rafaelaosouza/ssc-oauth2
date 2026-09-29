import express from 'express';
import session from 'express-session';
import { OAuth2Client } from 'google-auth-library';
import dotenv from 'dotenv';

dotenv.config({ path: 'process.env' });

const app = express();
const PORT = 3000;

const client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
);

// RBAC: e-mails desta lista recebem o papel "admin"; qualquer outro
// e-mail autenticado pelo Google recebe o papel "user".
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);

function resolveRole(email) {
    return ADMIN_EMAILS.includes(email.toLowerCase()) ? 'admin' : 'user';
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (ch) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
    }[ch]));
}

app.use(
    session({
        secret: process.env.SESSION_SECRET || 'dev-secret-troque-em-producao',
        resave: false,
        saveUninitialized: false,
    })
);

// Autenticação: exige que exista um usuário logado na sessão.
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/');
    }
    next();
}

// Autorização (RBAC): exige que o usuário logado tenha um papel específico.
function requireRole(role) {
    return (req, res, next) => {
        if (req.session.user.role !== role) {
            return res.status(403).send(`
                <h1>Acesso negado</h1>
                <p>Esta área é restrita ao papel "<strong>${role}</strong>".</p>
                <p>Seu papel atual: <strong>${req.session.user.role}</strong>.</p>
                <a href="/welcome">Voltar</a>
            `);
        }
        next();
    };
}

app.get('/', (req, res) => {
    const url = client.generateAuthUrl({
        access_type: 'offline',
        scope: ['email', 'profile', 'openid'],
    });

    res.send(`<a href="${url}">Login com Google</a>`);
});

app.get('/callback', async (req, res) => {
    try {
        const { code } = req.query;
        const { tokens } = await client.getToken(code);
        console.log("Tokens recebidos do Google:", tokens); // print no terminal do token
        client.setCredentials(tokens);

        const ticket = await client.verifyIdToken({
            idToken: tokens.id_token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();

        // O papel (role) é derivado do atributo "email" retornado pelo Google
        // e fica guardado na sessão do servidor por seguranca.
        req.session.user = {
            name: payload.name,
            email: payload.email,
            role: resolveRole(payload.email),
        };

        res.redirect('/welcome');
    } catch (error) {
        console.error('Erro na autenticação:', error);
        res.status(500).send('Erro ao autenticar com o Google.');
    }
});

app.get('/welcome', requireAuth, (req, res) => {
    const { name, email, role } = req.session.user;

    res.send(`
        <h1>Bem-vindo, ${name}!</h1>
        <p>Seu e-mail: ${email}</p>
        <p>Papel atribuído pelo RBAC: <strong>${role}</strong></p>
        <p>
            ${role === 'admin'
                ? 'Você possui permissão de administrador.'
                : 'Você possui permissão de usuário comum (sem acesso à área administrativa).'}
        </p>
        <p><a href="/admin">Tentar acessar a área administrativa</a></p>
        <form action="/logout" method="post"><button type="submit">Sair</button></form>
    `);
});

// Rota protegida por RBAC, somente o papel "admin" pode acessar.
app.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
    res.send(`
        <h1>Área administrativa</h1>
        <p>Acesso concedido pelo RBAC ao usuário ${escapeHtml(req.session.user.name)} (papel: admin).</p>
        <a href="/welcome">Voltar</a>
    `);
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});
