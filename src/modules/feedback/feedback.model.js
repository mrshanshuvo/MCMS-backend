const mongoose = require('mongoose');

const feedbackSchema = new mongoose.Schema(
  {
    campId: { type: mongoose.Schema.Types.ObjectId, ref: 'Camp', required: true },
    participantEmail: { type: String, required: true, lowercase: true, trim: true },
    participantName: { type: String, default: 'Anonymous', trim: true },
    participantPhotoURL: { type: String },
    rating: { type: Number, required: true, min: 1, max: 5 },
    feedback: { type: String, required: true },
    date: { type: Date, default: Date.now },
  },
  { collection: 'feedback', versionKey: false }
);

feedbackSchema.index({ campId: 1 });
feedbackSchema.index({ participantEmail: 1 });

module.exports = mongoose.model('Feedback', feedbackSchema);
