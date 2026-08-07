const { ObjectId } = require('mongodb');
const { getCollections } = require('../../config/db');

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
      { campName: { $regex: searchRegex } },
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
      sortOption = { campFees: 1 };
      break;
    case 'campFeesDesc':
      sortOption = { campFees: -1 };
      break;
    case 'alphabetical':
      sortOption = { campName: 1 };
      break;
    default:
      sortOption = { participantCount: -1 };
  }

  const { campsCollection } = getCollections();
  const total = await campsCollection.countDocuments(query);

  const camps = await campsCollection
    .find(query)
    .sort(sortOption)
    .skip((pageNum - 1) * limitNum)
    .limit(limitNum)
    .toArray();

  return {
    total,
    page: pageNum,
    limit: limitNum,
    totalPages: Math.ceil(total / limitNum),
    camps,
  };
};

const findCampByIdInDB = async (campId) => {
  const { campsCollection } = getCollections();
  return await campsCollection.findOne({ _id: new ObjectId(campId) });
};

const createCampInDB = async (campData, organizerEmail) => {
  const { campsCollection } = getCollections();
  const newCamp = {
    ...campData,
    organizerEmail,
    participantCount: 0,
    createdAt: new Date(),
  };
  return await campsCollection.insertOne(newCamp);
};

const findOrganizerCampsInDB = async (organizerEmail, page = 1, limit = 5) => {
  const skip = (page - 1) * limit;
  const query = { organizerEmail };
  const { campsCollection } = getCollections();

  const camps = await campsCollection.find(query).skip(skip).limit(limit).toArray();
  const totalCount = await campsCollection.countDocuments(query);

  return {
    camps,
    totalCount,
    currentPage: page,
    totalPages: Math.ceil(totalCount / limit),
  };
};

const incrementParticipantCountInDB = async (campId) => {
  const { campsCollection } = getCollections();
  return await campsCollection.updateOne(
    { _id: new ObjectId(campId) },
    { $inc: { participantCount: 1 } }
  );
};

const updateCampInDB = async (campId, organizerEmail, updateFields) => {
  const { campsCollection } = getCollections();

  const camp = await campsCollection.findOne({
    _id: new ObjectId(campId),
    organizerEmail,
  });

  if (!camp) return null;

  return await campsCollection.updateOne({ _id: new ObjectId(campId) }, { $set: updateFields });
};

const deleteCampInDB = async (campId, organizerEmail) => {
  const { campsCollection, registrationsCollection, paymentsCollection, feedbackCollection } =
    getCollections();

  const camp = await campsCollection.findOne({
    _id: new ObjectId(campId),
    organizerEmail,
  });

  if (!camp) return null;

  const result = await campsCollection.deleteOne({ _id: new ObjectId(campId) });

  if (result.deletedCount > 0) {
    await Promise.all([
      registrationsCollection.deleteMany({ campId: new ObjectId(campId) }),
      paymentsCollection.deleteMany({ campId: new ObjectId(campId) }),
      feedbackCollection.deleteMany({ campId: new ObjectId(campId) }),
    ]);
  }

  return result;
};

const findCampsWithRegistrationsInDB = async (email, page = 1, limit = 5) => {
  const { campsCollection } = getCollections();
  const skip = (page - 1) * limit;

  const [results, total] = await Promise.all([
    campsCollection
      .aggregate([
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
      ])
      .toArray(),
    campsCollection
      .aggregate([
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
      ])
      .toArray(),
  ]);

  return { results, totalCount: total[0]?.total || 0 };
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
