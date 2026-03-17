require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const Joi = require('joi');
const crypto = require('crypto'); // module natif Node — génère des tokens aléatoires sécurisés
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3000;
const resend = new Resend(process.env.RESEND_API_KEY);

// ─── Base de données ───────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      username   TEXT UNIQUE NOT NULL,
      email      TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Table des tokens de réinitialisation
  // Un token = une demande de reset, valable 1 heure
  // ON DELETE CASCADE = si l'utilisateur est supprimé, ses tokens le sont aussi
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token      TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);

  console.log('Base de données prête.');
}

// ─── Schémas de validation ─────────────────────────────────────────────────────
const registerSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .required()
    .messages({
      'string.alphanum': 'Le nom d\'utilisateur ne peut contenir que des lettres et chiffres.',
      'string.min': 'Le nom d\'utilisateur doit faire au moins 3 caractères.',
      'string.max': 'Le nom d\'utilisateur ne peut pas dépasser 30 caractères.',
      'any.required': 'Le nom d\'utilisateur est obligatoire.',
    }),

  email: Joi.string()
    .email({ tlds: { allow: false } })
    .required()
    .messages({
      'string.email': 'L\'adresse email n\'est pas valide.',
      'any.required': 'L\'email est obligatoire.',
    }),

  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/[A-Z]/, 'majuscule')
    .pattern(/[0-9]/, 'chiffre')
    .required()
    .messages({
      'string.min': 'Le mot de passe doit faire au moins 8 caractères.',
      'string.pattern.name': 'Le mot de passe doit contenir au moins une {#name}.',
      'any.required': 'Le mot de passe est obligatoire.',
    }),
});

const loginSchema = Joi.object({
  email: Joi.string().email({ tlds: { allow: false } }).required(),
  password: Joi.string().required(),
});

const forgotSchema = Joi.object({
  email: Joi.string().email({ tlds: { allow: false } }).required()
    .messages({ 'any.required': 'L\'email est obligatoire.' }),
});

const resetSchema = Joi.object({
  token: Joi.string().required(),
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/[A-Z]/, 'majuscule')
    .pattern(/[0-9]/, 'chiffre')
    .required()
    .messages({
      'string.min': 'Le mot de passe doit faire au moins 8 caractères.',
      'string.pattern.name': 'Le mot de passe doit contenir au moins une {#name}.',
      'any.required': 'Le mot de passe est obligatoire.',
    }),
});

// ─── Middleware de validation ──────────────────────────────────────────────────
function validate(schema) {
  return (req, res, next) => {
    const { error } = schema.validate(req.body, { abortEarly: false });
    if (error) {
      const messages = error.details.map(d => d.message);
      return res.status(400).json({ error: messages.join(' ') });
    }
    next();
  };
}

// ─── Middlewares ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-local-seulement',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24,
  },
}));

// ─── Middleware de protection ──────────────────────────────────────────────────
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login.html');
  next();
}

// ─── Routes API ───────────────────────────────────────────────────────────────

// POST /api/register
app.post('/api/register', validate(registerSchema), async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
      [username, email, hashedPassword]
    );
    res.json({ success: true, message: 'Compte créé avec succès !' });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Ce nom d\'utilisateur ou cet email est déjà pris.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// POST /api/login
app.post('/api/login', validate(loginSchema), async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({ success: true, message: `Bienvenue, ${user.username} !` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// GET /api/me
app.get('/api/me', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, email, created_at FROM users WHERE id = $1',
      [req.session.userId]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// POST /api/forgot-password
// Reçoit un email, génère un token, l'enregistre en DB, envoie le lien par email
app.post('/api/forgot-password', validate(forgotSchema), async (req, res) => {
  const { email } = req.body;

  try {
    const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    // Réponse identique que l'email existe ou non — évite de révéler quels emails sont enregistrés
    if (!user) {
      return res.json({ success: true, message: 'Si cet email existe, un lien vous a été envoyé.' });
    }

    // Supprime les anciens tokens de cet utilisateur avant d'en créer un nouveau
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [user.id]);

    // crypto.randomBytes(32) = 32 octets aléatoires → 64 caractères hex
    // C'est cryptographiquement sécurisé (contrairement à Math.random())
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // expire dans 1 heure

    await pool.query(
      'INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)',
      [token, user.id, expiresAt]
    );

    const resetUrl = `${process.env.APP_URL}/reset-password.html?token=${token}`;

    // resend.emails.send() ne throw PAS — il renvoie { data, error }
    // Il faut vérifier explicitement le champ error
    const { error: sendError } = await resend.emails.send({
      from: process.env.EMAIL_FROM || 'noreply@tondomaine.com',
      to: email,
      subject: 'Réinitialisation de votre mot de passe',
      html: `
        <p>Tu as demandé à réinitialiser ton mot de passe.</p>
        <p>Clique sur le lien ci-dessous (valable 1 heure) :</p>
        <p><a href="${resetUrl}">${resetUrl}</a></p>
        <p>Si tu n'es pas à l'origine de cette demande, ignore cet email.</p>
      `,
    });

    if (sendError) {
      console.error('[Resend] Échec envoi email :', sendError);
      return res.status(500).json({ error: 'Impossible d\'envoyer l\'email. Réessaie dans quelques instants.' });
    }

    res.json({ success: true, message: 'Si cet email existe, un lien vous a été envoyé.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// POST /api/reset-password
// Reçoit le token + nouveau mot de passe, vérifie le token, met à jour le mot de passe
app.post('/api/reset-password', validate(resetSchema), async (req, res) => {
  const { token, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM password_reset_tokens WHERE token = $1',
      [token]
    );
    const resetToken = result.rows[0];

    // Token inexistant ou expiré
    if (!resetToken || new Date() > new Date(resetToken.expires_at)) {
      await pool.query('DELETE FROM password_reset_tokens WHERE token = $1', [token]);
      return res.status(400).json({ error: 'Ce lien est invalide ou a expiré.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, resetToken.user_id]);

    // Token usage unique — on le supprime après utilisation
    await pool.query('DELETE FROM password_reset_tokens WHERE token = $1', [token]);

    res.json({ success: true, message: 'Mot de passe mis à jour. Tu peux te connecter.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ─── Vérification des variables d'environnement au démarrage ─────────────────
const REQUIRED_ENV = ['DATABASE_URL', 'SESSION_SECRET', 'RESEND_API_KEY', 'APP_URL', 'EMAIL_FROM'];
REQUIRED_ENV.forEach(key => {
  if (!process.env[key]) console.warn(`[WARN] Variable manquante : ${key}`);
});

// ─── Démarrage ────────────────────────────────────────────────────────────────
initDB()
  .then(() => {
    app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('Impossible de se connecter à la base de données :', err.message);
    process.exit(1);
  });
