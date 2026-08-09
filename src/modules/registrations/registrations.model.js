const mongoose = require('mongoose');

const registrationSchema = new mongoose.Schema(
  {
    campId: { type: mongoose.Schema.Types.ObjectId, ref: 'Camp', required: true },
    participantEmail: { type: String, required: true, lowercase: true, trim: true },
    participantName: { type: String, default: 'Anonymous', trim: true },
    age: { type: Number, required: true, min: 1 },
    phoneNumber: { type: String, required: true },
    gender: { type: String, required: true },
    emergencyContact: { type: String, required: true },
    registrationDate: { type: Date, default: Date.now },
    paymentStatus: {
      type: String,
      enum: ['Unpaid', 'Paid'],
      default: 'Unpaid',
    },
    confirmationStatus: {
      type: String,
      enum: ['Pending', 'Confirmed', 'Cancelled'],
      default: 'Pending',
    },
    transactionId: { type: String, unique: true, sparse: true },
  },
  { collection: 'registrations', versionKey: false }
);

registrationSchema.index({ participantEmail: 1 });
registrationSchema.index({ campId: 1 });

module.exports = mongoose.model('Registration', registrationSchema);
