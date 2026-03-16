const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = 3000;

// ─── Base de données ───────────────────────────────────────────────────────────
// SQLite crée automatiquement le fichier s'il n'existe pas
const db = new Database('users.db');

// On crée la table des utilisateurs si elle n'existe pas encore
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT    UNIQUE NOT NULL,
    email     TEXT    UNIQUE NOT NULL,
    password  TEXT    NOT NULL,
    created_at TEXT   DEFAULT (datetime('now'))
  )
`);

// ─── Middlewares ───────────────────────────────────────────────────────────────
app.use(express.json());                    // pour lire les corps JSON
app.use(express.urlencoded({ extended: true })); // pour lire les formulaires HTML
app.use(express.static('public'));          // sert les fichiers HTML/CSS/JS statiques

// Gestion des sessions (stockées côté serveur, un cookie est envoyé au navigateur)
app.use(session({
  secret: 'mon-secret-super-securise-a-changer-en-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,   // inaccessible via JavaScript côté client (protection XSS)
    maxAge: 1000 * 60 * 60 * 24  // 24 heures en millisecondes
  }
}));

// ─── Middleware de protection de routes ───────────────────────────────────────
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login.html');
  }
  next(); // l'utilisateur est connecté, on continue
}

// ─── Routes API ───────────────────────────────────────────────────────────────

// POST /api/register — Inscription
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;

  // Validation basique des champs
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Tous les champs sont obligatoires.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Le mot de passe doit faire au moins 6 caractères.' });
  }

  // Hashage du mot de passe (jamais stocker en clair !)
  // 10 = "cost factor" : plus c'est élevé, plus c'est lent (et sécurisé)
  const hashedPassword = bcrypt.hashSync(password, 10);

  try {
    const stmt = db.prepare(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)'
    );
    stmt.run(username, email, hashedPassword);

    res.json({ success: true, message: 'Compte créé avec succès !' });
  } catch (err) {
    // Erreur UNIQUE : username ou email déjà utilisé
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Ce nom d\'utilisateur ou cet email est déjà pris.' });
    }
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// POST /api/login — Connexion
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  // On vérifie si l'utilisateur existe ET si le mot de passe correspond au hash
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
  }

  // On sauvegarde l'ID en session (c'est ce qui "connecte" l'utilisateur)
  req.session.userId = user.id;
  req.session.username = user.username;

  res.json({ success: true, message: `Bienvenue, ${user.username} !` });
});

// POST /api/logout — Déconnexion
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// GET /api/me — Infos de l'utilisateur connecté (route protégée)
app.get('/api/me', requireLogin, (req, res) => {
  const user = db.prepare(
    'SELECT id, username, email, created_at FROM users WHERE id = ?'
  ).get(req.session.userId);

  res.json(user);
});

// ─── Démarrage du serveur ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`);
});
