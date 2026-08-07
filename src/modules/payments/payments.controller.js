const paymentsService = require('./payments.service');
const sendResponse = require('../../utils/response');

const createPaymentIntent = async (req, res) => {
  try {
    const { amount, campId } = req.body;
    const paymentIntent = await paymentsService.createPaymentIntentInDB(
      amount,
      campId,
      req.user.email
    );
    if (!paymentIntent) {
      return sendResponse(res, 200, { success: true, data: { clientSecret: null } });
    }
    return sendResponse(res, 200, {
      success: true,
      data: { clientSecret: paymentIntent.client_secret },
    });
  } catch (error) {
    console.error('Payment intent error:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to create payment intent' });
  }
};

const processPayment = async (req, res) => {
  try {
    const result = await paymentsService.processPaymentInDB(req.body, req.user.email);
    return sendResponse(res, 200, { success: true, data: result });
  } catch (error) {
    console.error('Payment processing error:', error);
    return sendResponse(res, 500, { success: false, message: error.message });
  }
};

const getPayments = async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 5;
    const result = await paymentsService.findPaymentsInDB(req.user.email, page, limit);
    return sendResponse(res, 200, {
      success: true,
      data: result.data,
      meta: result.pagination,
    });
  } catch (error) {
    console.error('Error fetching paginated payments:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch payments' });
  }
};

const getPaymentsByEmail = async (req, res) => {
  try {
    const { email } = req.query;
    if (req.user.email !== email) {
      return sendResponse(res, 403, { success: false, message: 'Unauthorized' });
    }
    const payments = await paymentsService.findPaymentsByEmailInDB(email);
    return sendResponse(res, 200, { success: true, data: payments });
  } catch (error) {
    console.error('Error fetching payments:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch payment history' });
  }
};

const stripeWebhook = async (req, res) => {
  const sig = req.headers['stripe-signature'];
  try {
    const result = await paymentsService.processStripeWebhookEvent(req.body, sig);
    return res.json(result);
  } catch (err) {
    console.error('Webhook error:', err);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
};

module.exports = {
  createPaymentIntent,
  processPayment,
  getPayments,
  getPaymentsByEmail,
  stripeWebhook,
};
