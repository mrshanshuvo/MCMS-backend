const mongoose = require('mongoose');

const campSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    location: { type: String, required: true, trim: true },
    fees: { type: Number, required: true, min: 0 },
    dateTime: { type: String, required: true },
    healthcareProfessional: { type: String, required: true, trim: true },
    description: { type: String },
    image: { type: String },
    organizerEmail: { type: String, required: true, lowercase: true, trim: true },
    participantCount: { type: Number, default: 0, min: 0 },
    createdAt: { type: Date, default: Date.now },
  },
  { collection: 'camps', versionKey: false }
);

campSchema.index({ organizerEmail: 1 });
campSchema.index({ campName: 'text', location: 'text', healthcareProfessional: 'text' });

module.exports = mongoose.model('Camp', campSchema);
