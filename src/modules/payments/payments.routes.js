const express = require('express');
const router = express.Router();
const paymentsController = require('./payments.controller');
const paymentsSchema = require('./payments.schema');
const validate = require('../../middlewares/validate.middleware');
const { verifyFBToken, verifyParticipant } = require('../../middlewares/auth.middleware');

router.post(
  '/create-payment-intent',
  verifyFBToken,
  verifyParticipant,
  validate(paymentsSchema.createPaymentIntentSchema),
  paymentsController.createPaymentIntent
);
router.post(
  '/payments',
  verifyFBToken,
  validate(paymentsSchema.processPaymentSchema),
  paymentsController.processPayment
);
router.get('/payments', verifyFBToken, paymentsController.getPayments);
router.get('/paymentsByEmail', verifyFBToken, paymentsController.getPaymentsByEmail);

module.exports = router;
