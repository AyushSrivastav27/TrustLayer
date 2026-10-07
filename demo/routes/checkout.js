import express from 'express';
import Stripe from 'stripe';

const router = express.Router();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder_key_123');

const schema = {
  parse(data) {
    if (!data || typeof data !== 'object') throw new Error('Invalid input');
    return data;
  }
};

/**
 * POST /api/checkout
 * 🔴 VULNERABILITY #6: Client-Controlled Payment Amount (Rule: payment/payment-amount-tampering)
 * 🟠 VULNERABILITY #7: Sensitive Route Missing Auth (Rule: auth/missing-auth-middleware)
 */
router.post('/checkout', async (req, res) => {
  const data = schema.parse(req.body);

  try {
    // Client-controlled amount passed directly to payment processor
    const charge = await stripe.charges.create({
      amount: req.body.amount,
      currency: 'usd',
      source: data.source || 'tok_visa'
    });

    res.json({ success: true, chargeId: charge.id });
  } catch (err) {
    res.status(500).json({ error: 'Payment failed', message: err.message });
  }
});

export default router;
