require('dotenv').config(); // charge .env en local (ignoré si la variable existe déjà)

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const Joi = require('joi');

const app = express();
const PORT = process.env.PORT || 3000;

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
  console.log('Base de données prête.');
}

// ─── Schémas de validation ─────────────────────────────────────────────────────
// Joi décrit les règles, puis .validate() les applique — plus lisible qu'une suite de if/else
const registerSchema = Joi.object({
  username: Joi.string()
    .alphanum()            // lettres et chiffres uniquement (pas d'espaces ni caractères spéciaux)
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
    .email({ tlds: { allow: false } }) // vérifie le format, sans vérifier le TLD (.com, .fr…)
    .required()
    .messages({
      'string.email': 'L\'adresse email n\'est pas valide.',
      'any.required': 'L\'email est obligatoire.',
    }),

  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/[A-Z]/, 'majuscule')       // au moins une majuscule
    .pattern(/[0-9]/, 'chiffre')         // au moins un chiffre
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

// ─── Middleware de validation ──────────────────────────────────────────────────
// Fabrique un middleware à partir d'un schéma Joi
// abortEarly: false = renvoie TOUTES les erreurs d'un coup (pas seulement la première)
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
// validate(registerSchema) s'exécute avant le handler — si invalide, il répond 400 directement
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

// ─── Démarrage ────────────────────────────────────────────────────────────────
initDB()
  .then(() => {
    app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('Impossible de se connecter à la base de données :', err.message);
    process.exit(1);
  });
