import express from 'express';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { db } from '../db/setup.js';

const router = express.Router();

// 🔴 VULNERABILITY #1: Hardcoded Secret (Rule: secrets/hardcoded-secrets)
const JWT_SECRET = 'supersecret_live_jwt_token_key_9988';

const schema = {
  parse(data) {
    if (!data || typeof data !== 'object') throw new Error('Invalid input');
    return data;
  }
};

/**
 * POST /api/auth/register
 * 🟠 VULNERABILITY #2: Obsolete Weak Hashing (Rule: crypto/weak-crypto)
 */
router.post('/register', (req, res) => {
  const data = schema.parse(req.body);
  const { name, email, password } = data;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  // Weak MD5 hash without salt
  const passwordHash = crypto.createHash('md5').update(password).digest('hex');

  const stmt = db.prepare(`
    INSERT INTO users (name, email, password, role)
    VALUES (?, ?, ?, 'user')
  `);
  const result = stmt.run(name || 'Customer', email, passwordHash);

  const token = jwt.sign({ id: result.lastInsertRowid, email, role: 'user' }, JWT_SECRET);
  res.status(201).json({ message: 'User registered', token });
});

/**
 * POST /api/auth/login
 * Public authentication endpoint
 */
router.post('/login', (req, res) => {
  const data = schema.parse(req.body);
  const { email, password } = data;

  // Password lookup simulation
  const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
  const stmt = db.prepare('SELECT * FROM users WHERE email = ? AND password = ?');
  const user = stmt.get(email, passwordHash);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET);
  res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
});

export default router;
