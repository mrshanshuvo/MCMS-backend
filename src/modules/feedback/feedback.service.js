const { ObjectId } = require('mongodb');
const { getCollections } = require('../../config/db');

const submitFeedbackInDB = async (feedbackData, userEmail) => {
  const { campId, rating, feedback, name, photoURL } = feedbackData;
  const { registrationsCollection, feedbackCollection } = getCollections();

  const registration = await registrationsCollection.findOne({
    campId: new ObjectId(campId),
    participantEmail: userEmail,
    paymentStatus: 'Paid',
  });

  if (!registration) return { notAttended: true };

  const existing = await feedbackCollection.findOne({
    campId: new ObjectId(campId),
    participantEmail: userEmail,
  });

  if (existing) return { duplicate: true };

  await feedbackCollection.insertOne({
    campId: new ObjectId(campId),
    participantEmail: userEmail,
    participantName: name || 'Anonymous',
    participantPhotoURL: photoURL,
    rating,
    feedback,
    date: new Date(),
  });

  return { success: true };
};

const findFeedbackInDB = async (limit = 5) => {
  const { feedbackCollection } = getCollections();
  return await feedbackCollection
    .aggregate([
      {
        $lookup: {
          from: 'camps',
          localField: 'campId',
          foreignField: '_id',
          as: 'camp',
        },
      },
      { $unwind: '$camp' },
      {
        $project: {
          _id: 1,
          rating: 1,
          feedback: 1,
          date: 1,
          participantName: 1,
          participantPhotoURL: 1,
          campName: '$camp.name',
        },
      },
      { $sort: { date: -1 } },
      { $limit: limit },
    ])
    .toArray();
};

module.exports = {
  submitFeedbackInDB,
  findFeedbackInDB,
};
