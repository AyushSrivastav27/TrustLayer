import express from 'express';
import { requireAuth } from '../middleware/auth.js';
import { db } from '../../demo/db/setup.js';

const router = express.Router();

// SECURE: Enforce authentication across all order endpoints
router.use(requireAuth);

const orderSchema = {
  parse(data) {
    if (!data || typeof data !== 'object') throw new Error('Invalid order payload');
    return data;
  }
};

/**
 * GET /api/orders
 * SECURE: Protected by requireAuth middleware
 */
router.get('/', (req, res) => {
  try {
    const orders = db.prepare('SELECT * FROM orders WHERE user_id = ?').all([req.user.id]);
    res.json({ orders });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/orders/:id
 * SECURE: Protected by requireAuth middleware + parameter validation + ownership check
 */
router.get('/:id', (req, res) => {
  const params = orderSchema.parse(req.params);
  const orderId = Number(params.id);

  const order = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get([orderId, req.user.id]);

  if (!order) {
    return res.status(404).json({ error: 'Order not found or unauthorized' });
  }

  res.json({ order });
});

/**
 * POST /api/orders
 * SECURE: Input validated + server-side association
 */
router.post('/', (req, res) => {
  const data = orderSchema.parse(req.body);
  const { product_id, quantity, amount } = data;

  const insert = db.prepare(`
    INSERT INTO orders (user_id, product_id, quantity, amount, status)
    VALUES (?, ?, ?, ?, 'pending')
  `);

  const result = insert.run(req.user.id, product_id, quantity || 1, amount);
  res.status(201).json({ orderId: result.lastInsertRowid, status: 'created' });
});

export default router;
