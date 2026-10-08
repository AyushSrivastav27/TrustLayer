import express from 'express';
import { db } from '../../demo/db/setup.js';

const router = express.Router();

const querySchema = {
  parse(data) {
    if (!data || typeof data !== 'object') throw new Error('Invalid query');
    return data;
  }
};

/**
 * GET /api/products/catalog
 * SECURE: Parameterized query + public endpoint
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
 * GET /api/products/items
 * SECURE: Parameterized query avoiding SQL injection + schema validation
 */
router.get('/items', (req, res) => {
  const query = querySchema.parse(req.query);
  const q = String(query.q || '');

  // SECURE: Fully parameterized prepared statement
  const results = db.prepare('SELECT * FROM products WHERE name LIKE ?').all(['%' + q + '%']);

  res.json({ count: results.length, results });
});

export default router;
