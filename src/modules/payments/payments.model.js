const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema(
  {
    campId: { type: mongoose.Schema.Types.ObjectId, ref: 'Camp', required: true },
    registrationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Registration', required: true },
    participantEmail: { type: String, required: true, lowercase: true, trim: true },
    transactionId: { type: String, required: true },
    amount: { type: Number, required: true, min: 0 },
    paymentMethod: { type: String, default: 'Stripe' },
    paymentDate: { type: Date, default: Date.now },
    status: {
      type: String,
      enum: ['Pending', 'Completed', 'Failed', 'Refunded'],
      default: 'Pending',
    },
  },
  { collection: 'payments', versionKey: false }
);

paymentSchema.index({ participantEmail: 1 });
paymentSchema.index({ campId: 1 });

module.exports = mongoose.model('Payment', paymentSchema);
