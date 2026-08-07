const { z } = require('zod');

const objectIdRegex = /^[0-9a-fA-F]{24}$/;
const objectIdSchema = z.string().regex(objectIdRegex, 'Invalid ObjectId format');

const createPaymentIntentSchema = {
  body: z.object({
    amount: z.number().min(0, 'Amount must be positive'),
    campId: objectIdSchema,
  }),
};

const processPaymentSchema = {
  body: z.object({
    campId: objectIdSchema,
    registrationId: objectIdSchema,
    transactionId: z.string().min(1, 'Transaction ID is required'),
    amount: z.number().min(0, 'Amount must be positive'),
    paymentMethod: z.string().optional(),
  }),
};

module.exports = {
  createPaymentIntentSchema,
  processPaymentSchema,
};
