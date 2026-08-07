const express = require('express');
const router = express.Router();
const paymentsController = require('./payments.controller');
const { verifyFBToken, verifyParticipant } = require('../../middlewares/auth.middleware');

router.post(
  '/create-payment-intent',
  verifyFBToken,
  verifyParticipant,
  paymentsController.createPaymentIntent
);
router.post('/payments', verifyFBToken, paymentsController.processPayment);
router.get('/payments', verifyFBToken, paymentsController.getPayments);
router.get('/paymentsByEmail', verifyFBToken, paymentsController.getPaymentsByEmail);

module.exports = router;
