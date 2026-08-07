const { getCollections } = require('../../config/db');

const findSuccessStoriesInDB = async () => {
  const { successStoriesCollection } = getCollections();
  return await successStoriesCollection.find().toArray();
};

const findFaqsInDB = async () => {
  const { faqCollection } = getCollections();
  return await faqCollection.find().toArray();
};

const findBlogsInDB = async () => {
  const { blogCollection } = getCollections();
  return await blogCollection.find().toArray();
};

module.exports = {
  findSuccessStoriesInDB,
  findFaqsInDB,
  findBlogsInDB,
};
