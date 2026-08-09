const mongoose = require('mongoose');
const Registration = require('../registrations/registrations.model');
const Payment = require('./payments.model');

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
    metadata: { campId: campId.toString(), participantEmail },
  });
};

const processPaymentInDB = async (paymentData, userEmail) => {
  const { campId, registrationId, transactionId, amount, paymentMethod } = paymentData;
  const session = await mongoose.connection.startSession();

  try {
    await session.withTransaction(async () => {
      const registration = await Registration.findOne(
        { _id: registrationId, participantEmail: userEmail },
        null,
        { session }
      );

      if (!registration) throw new Error('Registration not found');
      if (registration.paymentStatus === 'Paid') throw new Error('Payment already processed');

      await Registration.findByIdAndUpdate(
        registration._id,
        {
          $set: {
            paymentStatus: 'Paid',
            confirmationStatus: 'Confirmed',
            transactionId,
          },
        },
        { session }
      );

      await Payment.create(
        [
          {
            campId,
            registrationId,
            participantEmail: userEmail,
            transactionId,
            amount,
            paymentMethod,
            paymentDate: new Date(),
            status: 'Completed',
          },
        ],
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

  const [total, payments] = await Promise.all([
    Payment.countDocuments(query),
    Payment.find(query).sort({ paymentDate: -1 }).skip(skip).limit(limit).lean(),
  ]);

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
  return await Payment.find(filter).sort({ paymentDate: -1 }).lean();
};

const processStripeWebhookEvent = async (reqBody, sig) => {
  const stripe = getStripe();
  const event = stripe.webhooks.constructEvent(reqBody, sig, process.env.STRIPE_WEBHOOK_SECRET);

  if (event.type === 'payment_intent.succeeded') {
    const paymentIntent = event.data.object;
    const { campId, participantEmail } = paymentIntent.metadata;

    await Registration.findOneAndUpdate(
      {
        campId,
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
