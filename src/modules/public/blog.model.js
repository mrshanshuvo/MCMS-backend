const mongoose = require('mongoose');

const blogSchema = new mongoose.Schema(
  {},
  { collection: 'blogs', strict: false, versionKey: false }
);

module.exports = mongoose.model('Blog', blogSchema);
