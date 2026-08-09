const Feedback = require('./feedback.model');
const Registration = require('../registrations/registrations.model');

const submitFeedbackInDB = async (feedbackData, userEmail) => {
  const { campId, rating, feedback, name, photoURL } = feedbackData;

  const registration = await Registration.findOne({
    campId,
    participantEmail: userEmail,
    paymentStatus: 'Paid',
  });

  if (!registration) return { notAttended: true };

  const existing = await Feedback.findOne({ campId, participantEmail: userEmail });
  if (existing) return { duplicate: true };

  await Feedback.create({
    campId,
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
  return await Feedback.aggregate([
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
  ]);
};

module.exports = {
  submitFeedbackInDB,
  findFeedbackInDB,
};
