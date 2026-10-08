import express from 'express';
import { db } from '../db/setup.js';

const router = express.Router();

const schema = {
  parse(data) {
    if (!data || typeof data !== 'object') throw new Error('Invalid query');
    return data;
  }
};

/**
 * GET /api/products/catalog
 * Public product listing
 */
router.get('/catalog', (req, res) => {
  try {
    const products = db.prepare('SELECT * FROM products').all();
    res.json({ products });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/products/search
 * 🔴 VULNERABILITY #3: SQL Injection via template literal (Rule: injection/sql-injection)
 */
router.get('/products/search', (req, res) => {
  const query = schema.parse(req.query);
  const q = query.q || '';

  // Vulnerable: dynamic string template literal directly executed on DB
  const results = db.all(`SELECT * FROM products WHERE name LIKE '%${q}%'`);

  res.json({ count: results.length, results });
});

export default router;
