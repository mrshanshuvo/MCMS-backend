const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema(
  {
    userEmail: { type: String, required: true, lowercase: true, trim: true },
    title: { type: String, required: true },
    message: { type: String, required: true },
    type: {
      type: String,
      enum: ['registration', 'payment', 'system'],
      default: 'system',
    },
    link: { type: String, default: '' },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
  },
  { collection: 'notifications', versionKey: false }
);

notificationSchema.index({ userEmail: 1, read: 1 });

module.exports = mongoose.model('Notification', notificationSchema);
