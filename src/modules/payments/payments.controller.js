const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { ObjectId } = require('mongodb');
const { getCollections, client } = require('../../config/db');

const createPaymentIntent = async (req, res) => {
  try {
    const { amount, campId } = req.body;
    if (amount === 0) {
      return res.json({ clientSecret: null });
    }
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount * 100,
      currency: 'usd',
      metadata: { campId, participantEmail: req.user.email },
    });
    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    console.error('Payment intent error:', error);
    res.status(500).json({ error: 'Failed to create payment intent' });
  }
};

const processPayment = async (req, res) => {
  const session = client.startSession();
  try {
    const { campId, registrationId, transactionId, amount, paymentMethod } = req.body;
    const { registrationsCollection, paymentsCollection } = getCollections();

    await session.withTransaction(async () => {
      const registration = await registrationsCollection.findOne(
        {
          _id: new ObjectId(registrationId),
          participantEmail: req.user.email,
        },
        { session }
      );

      if (!registration) throw new Error('Registration not found');
      if (registration.paymentStatus === 'Paid') throw new Error('Payment already processed');

      await registrationsCollection.updateOne(
        { _id: registration._id },
        {
          $set: {
            paymentStatus: 'Paid',
            confirmationStatus: 'Confirmed',
            transactionId,
          },
        },
        { session }
      );

      await paymentsCollection.insertOne(
        {
          campId: new ObjectId(campId),
          registrationId: new ObjectId(registrationId),
          participantEmail: req.user.email,
          transactionId,
          amount: amount,
          paymentMethod,
          paymentDate: new Date(),
          status: 'Completed',
        },
        { session }
      );
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Payment processing error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    await session.endSession();
  }
};

const getPayments = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;

    const query = { participantEmail: req.user.email };
    const { paymentsCollection } = getCollections();

    const total = await paymentsCollection.countDocuments(query);
    const payments = await paymentsCollection
      .find(query)
      .sort({ paymentDate: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    res.json({
      data: payments,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error('Error fetching paginated payments:', error);
    res.status(500).json({ error: 'Failed to fetch payments' });
  }
};

const getPaymentsByEmail = async (req, res) => {
  try {
    const { email } = req.query;

    if (req.user.email !== email) {
      return res.status(403).send({
        success: false,
        message: 'Unauthorized',
      });
    }

    const filter = email ? { participantEmail: email } : {};
    const { paymentsCollection } = getCollections();

    const payments = await paymentsCollection.find(filter).sort({ payment_time: -1 }).toArray();

    res.send({ success: true, data: payments });
  } catch (error) {
    console.error('Error fetching payments:', error);
    res.status(500).send({ success: false, message: 'Failed to fetch payment history' });
  }
};

const stripeWebhook = async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook error:', err);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'payment_intent.succeeded') {
    const paymentIntent = event.data.object;
    const { campId, participantEmail } = paymentIntent.metadata;

    try {
      const { registrationsCollection } = getCollections();
      await registrationsCollection.updateOne(
        {
          campId: new ObjectId(campId),
          participantEmail,
          transactionId: paymentIntent.id,
        },
        {
          $set: {
            paymentStatus: 'Paid',
            confirmationStatus: 'Confirmed',
          },
        }
      );
    } catch (error) {
      console.error('Webhook update error:', error);
    }
  }

  res.json({ received: true });
};

module.exports = {
  createPaymentIntent,
  processPayment,
  getPayments,
  getPaymentsByEmail,
  stripeWebhook,
};
