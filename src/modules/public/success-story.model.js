const mongoose = require('mongoose');

const successStorySchema = new mongoose.Schema(
  {},
  { collection: 'success_stories', strict: false, versionKey: false }
);

module.exports = mongoose.model('SuccessStory', successStorySchema);
