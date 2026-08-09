const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    name: { type: String, trim: true },
    photoURL: { type: String },
    role: {
      type: String,
      enum: ['participant', 'organizer'],
      default: 'participant',
    },
    phone: { type: String },
    address: { type: String },
    created_at: { type: String },
    last_login: { type: String },
  },
  { collection: 'users', versionKey: false }
);

module.exports = mongoose.model('User', userSchema);
