import express from 'express';
import { db } from '../db/setup.js';

const router = express.Router();

/**
 * GET /api/orders/:id
 * 🟠 VULNERABILITY #4: Missing Authentication Middleware (Rule: auth/missing-auth-middleware)
 * 🟠 VULNERABILITY #5: Missing Input Validation (Rule: injection/missing-input-validation)
 */
router.get('/orders/:id', (req, res) => {
  // Direct access to req.params without validation
  const orderId = req.params.id;
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);

  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  res.json({ order });
});

export default router;
