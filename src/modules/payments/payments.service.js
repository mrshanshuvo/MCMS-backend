const { ObjectId } = require('mongodb');
const { getCollections, client } = require('../../config/db');

let stripeInstance;
const getStripe = () => {
  if (!stripeInstance) {
    const stripe = require('stripe');
    stripeInstance = stripe(process.env.STRIPE_SECRET_KEY);
  }
  return stripeInstance;
};

const createPaymentIntentInDB = async (amount, campId, participantEmail) => {
  if (amount === 0) return null;
  const stripe = getStripe();
  return await stripe.paymentIntents.create({
    amount: amount * 100,
    currency: 'usd',
    metadata: { campId, participantEmail },
  });
};

const processPaymentInDB = async (paymentData, userEmail) => {
  const { campId, registrationId, transactionId, amount, paymentMethod } = paymentData;
  const { registrationsCollection, paymentsCollection } = getCollections();
  const session = client.startSession();

  try {
    await session.withTransaction(async () => {
      const registration = await registrationsCollection.findOne(
        {
          _id: new ObjectId(registrationId),
          participantEmail: userEmail,
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
          participantEmail: userEmail,
          transactionId,
          amount,
          paymentMethod,
          paymentDate: new Date(),
          status: 'Completed',
        },
        { session }
      );
    });

    // Trigger Notification for Participant
    try {
      const { createNotification } = require('../notifications/notifications.service');
      await createNotification({
        userEmail,
        title: 'Payment Successful',
        message: `Your payment of $${amount} for registration was completed successfully.`,
        type: 'payment',
        link: '/dashboard/payment-history',
      });
    } catch (err) {
      console.error('Payment notification error:', err);
    }

    return { success: true };
  } finally {
    await session.endSession();
  }
};

const findPaymentsInDB = async (userEmail, page = 1, limit = 5) => {
  const skip = (page - 1) * limit;
  const query = { participantEmail: userEmail };
  const { paymentsCollection } = getCollections();

  const total = await paymentsCollection.countDocuments(query);
  const payments = await paymentsCollection
    .find(query)
    .sort({ paymentDate: -1 })
    .skip(skip)
    .limit(limit)
    .toArray();

  return {
    data: payments,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    },
  };
};

const findPaymentsByEmailInDB = async (email) => {
  const filter = email ? { participantEmail: email } : {};
  const { paymentsCollection } = getCollections();
  return await paymentsCollection.find(filter).sort({ payment_time: -1 }).toArray();
};

const processStripeWebhookEvent = async (reqBody, sig) => {
  const stripe = getStripe();
  const event = stripe.webhooks.constructEvent(reqBody, sig, process.env.STRIPE_WEBHOOK_SECRET);

  if (event.type === 'payment_intent.succeeded') {
    const paymentIntent = event.data.object;
    const { campId, participantEmail } = paymentIntent.metadata;
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
  }

  return { received: true };
};

module.exports = {
  createPaymentIntentInDB,
  processPaymentInDB,
  findPaymentsInDB,
  findPaymentsByEmailInDB,
  processStripeWebhookEvent,
};
