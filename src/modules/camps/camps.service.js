const Camp = require('./camps.model');
const Registration = require('../registrations/registrations.model');
const Payment = require('../payments/payments.model');
const Feedback = require('../feedback/feedback.model');

const escapeRegex = (string) => string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const findAllCampsInDB = async ({
  search = '',
  sort = 'participantCount',
  page = '1',
  limit = '6',
}) => {
  const pageNum = parseInt(page, 10);
  const limitNum = parseInt(limit, 10);
  const searchRegex = new RegExp(escapeRegex(search), 'i');

  const query = {
    $or: [
      { name: { $regex: searchRegex } },
      { location: { $regex: searchRegex } },
      { healthcareProfessional: { $regex: searchRegex } },
    ],
  };

  let sortOption;
  switch (sort) {
    case 'participantCount':
      sortOption = { participantCount: -1 };
      break;
    case 'campFeesAsc':
      sortOption = { fees: 1 };
      break;
    case 'campFeesDesc':
      sortOption = { fees: -1 };
      break;
    case 'alphabetical':
      sortOption = { name: 1 };
      break;
    default:
      sortOption = { participantCount: -1 };
  }

  const [total, camps] = await Promise.all([
    Camp.countDocuments(query),
    Camp.find(query)
      .sort(sortOption)
      .skip((pageNum - 1) * limitNum)
      .limit(limitNum)
      .lean(),
  ]);

  return {
    camps,
    meta: {
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum),
    },
  };
};

const findCampByIdInDB = async (campId) => {
  return await Camp.findById(campId).lean();
};

const createCampInDB = async (campData, organizerEmail) => {
  return await Camp.create({
    ...campData,
    organizerEmail,
    participantCount: 0,
    createdAt: new Date(),
  });
};

const findOrganizerCampsInDB = async (organizerEmail, page = 1, limit = 5) => {
  const skip = (page - 1) * limit;
  const query = { organizerEmail };

  const [camps, totalCount] = await Promise.all([
    Camp.find(query).skip(skip).limit(limit).lean(),
    Camp.countDocuments(query),
  ]);

  return {
    camps,
    meta: {
      total: totalCount,
      page,
      limit,
      totalPages: Math.ceil(totalCount / limit),
    },
  };
};

const incrementParticipantCountInDB = async (campId) => {
  return await Camp.findByIdAndUpdate(campId, { $inc: { participantCount: 1 } });
};

const updateCampInDB = async (campId, organizerEmail, updateFields) => {
  const camp = await Camp.findOne({ _id: campId, organizerEmail });
  if (!camp) return null;

  return await Camp.findByIdAndUpdate(campId, { $set: updateFields }, { new: true });
};

const deleteCampInDB = async (campId, organizerEmail) => {
  const camp = await Camp.findOne({ _id: campId, organizerEmail });
  if (!camp) return null;

  const result = await Camp.findByIdAndDelete(campId);

  if (result) {
    await Promise.all([
      Registration.deleteMany({ campId }),
      Payment.deleteMany({ campId }),
      Feedback.deleteMany({ campId }),
    ]);
  }

  return result;
};

const findCampsWithRegistrationsInDB = async (email, page = 1, limit = 5) => {
  const skip = (page - 1) * limit;

  const [results, totalArr] = await Promise.all([
    Camp.aggregate([
      {
        $lookup: {
          from: 'registrations',
          let: { campIdObj: '$_id' },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ['$campId', '$$campIdObj'] },
                    { $eq: ['$participantEmail', email] },
                  ],
                },
              },
            },
            {
              $project: {
                _id: 1,
                participantName: 1,
                paymentStatus: 1,
                confirmationStatus: 1,
                registrationDate: 1,
              },
            },
          ],
          as: 'participants',
        },
      },
      { $match: { 'participants.0': { $exists: true } } },
      {
        $lookup: {
          from: 'feedback',
          let: { campIdObj: '$_id' },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ['$campId', '$$campIdObj'] },
                    { $eq: ['$participantEmail', email] },
                  ],
                },
              },
            },
            { $limit: 1 },
          ],
          as: 'userFeedback',
        },
      },
      {
        $addFields: {
          hasFeedback: { $gt: [{ $size: '$userFeedback' }, 0] },
        },
      },
      {
        $project: {
          _id: 1,
          name: 1,
          dateTime: 1,
          location: 1,
          fees: 1,
          healthcareProfessional: 1,
          participants: 1,
          hasFeedback: 1,
        },
      },
      { $skip: skip },
      { $limit: limit },
    ]),
    Camp.aggregate([
      {
        $lookup: {
          from: 'registrations',
          let: { campIdObj: '$_id' },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ['$campId', '$$campIdObj'] },
                    { $eq: ['$participantEmail', email] },
                  ],
                },
              },
            },
          ],
          as: 'participants',
        },
      },
      { $match: { 'participants.0': { $exists: true } } },
      { $count: 'total' },
    ]),
  ]);

  const totalCount = totalArr[0]?.total || 0;

  return {
    results,
    meta: {
      total: totalCount,
      page,
      limit,
      totalPages: Math.ceil(totalCount / limit),
    },
  };
};

module.exports = {
  findAllCampsInDB,
  findCampByIdInDB,
  createCampInDB,
  findOrganizerCampsInDB,
  incrementParticipantCountInDB,
  updateCampInDB,
  deleteCampInDB,
  findCampsWithRegistrationsInDB,
};
