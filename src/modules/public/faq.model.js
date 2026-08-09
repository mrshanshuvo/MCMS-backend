const mongoose = require('mongoose');

const faqSchema = new mongoose.Schema({}, { collection: 'faq', strict: false, versionKey: false });

module.exports = mongoose.model('Faq', faqSchema);
