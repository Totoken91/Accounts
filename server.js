require('dotenv').config(); // charge .env en local (ignoré si la variable existe déjà)

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Base de données ───────────────────────────────────────────────────────────
// Pool = groupe de connexions réutilisables (plus efficace qu'une connexion unique)
// Railway injecte automatiquement DATABASE_URL dans les variables d'env
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // SSL activé dès que DATABASE_URL est défini (Railway, Neon, Supabase…)
  // En local sans DATABASE_URL, pg utilise localhost sans SSL
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Création de la table au démarrage si elle n'existe pas
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
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Tous les champs sont obligatoires.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Le mot de passe doit faire au moins 6 caractères.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
      [username, email, hashedPassword]
      // $1, $2, $3 = paramètres numérotés en PostgreSQL (vs ? en SQLite)
    );
    res.json({ success: true, message: 'Compte créé avec succès !' });
  } catch (err) {
    // Code 23505 = violation de contrainte UNIQUE en PostgreSQL
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Ce nom d\'utilisateur ou cet email est déjà pris.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis.' });
  }

  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0]; // pg retourne toujours un objet { rows: [...] }

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
  }

  req.session.userId = user.id;
  req.session.username = user.username;

  res.json({ success: true, message: `Bienvenue, ${user.username} !` });
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// GET /api/me
app.get('/api/me', requireLogin, async (req, res) => {
  const result = await pool.query(
    'SELECT id, username, email, created_at FROM users WHERE id = $1',
    [req.session.userId]
  );
  res.json(result.rows[0]);
});

// ─── Démarrage ────────────────────────────────────────────────────────────────
initDB()
  .then(() => {
    app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('Impossible de se connecter à la base de données.');
    console.error('Code :', err.code);
    console.error('Message :', err.message);
    console.error('DATABASE_URL défini :', !!process.env.DATABASE_URL);
    process.exit(1);
  });
