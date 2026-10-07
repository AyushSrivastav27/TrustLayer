import express from 'express';
import { db } from '../db/setup.js';

const router = express.Router();

const schema = {
  parse(data) {
    if (!data || typeof data !== 'object') throw new Error('Invalid input');
    return data;
  }
};

/**
 * POST /api/webhook/public/webhook
 * 🟠 VULNERABILITY #8: Missing Webhook Signature Verification (Rule: payment/missing-webhook-verification)
 */
router.post('/public/webhook', (req, res) => {
  // Directly trusting unverified event payload
  const event = schema.parse(req.body);

  if (event.type === 'payment_intent.succeeded') {
    const paymentIntent = event.data?.object;
    const orderId = paymentIntent?.metadata?.orderId;

    if (orderId) {
      const stmt = db.prepare('UPDATE orders SET status = ? WHERE id = ?');
      stmt.run('completed', orderId);
    }
  }

  res.json({ received: true });
});

export default router;
