const { ObjectId } = require('mongodb');
const { getCollections } = require('../../config/db');

const escapeRegex = (string) => string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const registerForCampInDB = async (registrationData) => {
  const { campId, participantName, participantEmail, age, phoneNumber, gender, emergencyContact } =
    registrationData;

  const { registrationsCollection } = getCollections();

  const existing = await registrationsCollection.findOne({
    campId: new ObjectId(campId),
    participantEmail,
  });

  if (existing) return { duplicate: true };

  const newRegistration = {
    campId: new ObjectId(campId),
    participantEmail,
    participantName: participantName || 'Anonymous',
    age: parseInt(age, 10),
    phoneNumber,
    gender,
    emergencyContact,
    registrationDate: new Date(),
    paymentStatus: 'Unpaid',
    confirmationStatus: 'Pending',
  };

  const result = await registrationsCollection.insertOne(newRegistration);
  return { success: true, registrationId: result.insertedId };
};

const checkRegistrationInDB = async (campId, email) => {
  const { registrationsCollection } = getCollections();
  const registration = await registrationsCollection.findOne({
    campId: new ObjectId(campId),
    participantEmail: email,
  });
  return !!registration;
};

const deleteRegistrationInDB = async (id, requestingEmail) => {
  const { registrationsCollection, campsCollection, usersCollection } = getCollections();

  const registration = await registrationsCollection.findOne({
    _id: new ObjectId(id),
  });

  if (!registration) return null;

  const requestingUser = await usersCollection.findOne({ email: requestingEmail });

  if (registration.participantEmail !== requestingEmail && requestingUser?.role !== 'organizer') {
    return { forbidden: true };
  }

  await registrationsCollection.deleteOne({ _id: new ObjectId(id) });
  await campsCollection.updateOne({ _id: registration.campId }, { $inc: { participantCount: -1 } });

  return { success: true };
};

const findAllRegistrationsInDB = async (queryParams) => {
  const {
    page = 1,
    limit = 10,
    search = '',
    status = 'all',
    campId,
    sortBy = 'registrationDate',
    sortOrder = 'desc',
  } = queryParams;

  const pageNumber = Math.max(parseInt(page, 10), 1);
  const limitNumber = Math.min(Math.max(parseInt(limit, 10), 1), 100);
  const sortDirection = sortOrder === 'asc' ? 1 : -1;

  const filter = {};
  if (status !== 'all') filter.confirmationStatus = status;
  if (campId && ObjectId.isValid(campId)) filter.campId = new ObjectId(campId);

  if (search) {
    const searchRegex = new RegExp(escapeRegex(search), 'i');
    filter.$or = [
      { participantName: searchRegex },
      { participantEmail: searchRegex },
      { transactionId: searchRegex },
    ];
  }

  const { registrationsCollection, campsCollection } = getCollections();
  const totalCount = await registrationsCollection.countDocuments(filter);

  const registrations = await registrationsCollection
    .find(filter)
    .sort({ [sortBy]: sortDirection })
    .skip((pageNumber - 1) * limitNumber)
    .limit(limitNumber)
    .toArray();

  const campIds = [...new Set(registrations.map((r) => r.campId))];
  const camps = await campsCollection.find({ _id: { $in: campIds } }).toArray();

  const campMap = camps.reduce((map, camp) => {
    map[camp._id] = camp;
    return map;
  }, {});

  const enrichedRegistrations = registrations.map((reg) => ({
    ...reg,
    campName: campMap[reg.campId]?.name || 'Unknown Camp',
    campFees: campMap[reg.campId]?.fees || 0,
    campLocation: campMap[reg.campId]?.location || 'Unknown Location',
  }));

  return {
    data: enrichedRegistrations,
    pagination: {
      page: pageNumber,
      limit: limitNumber,
      totalCount,
      totalPages: Math.ceil(totalCount / limitNumber),
    },
  };
};

const cancelRegistrationInDB = async (campId, email) => {
  const { registrationsCollection, campsCollection } = getCollections();

  const registration = await registrationsCollection.findOne({
    campId: new ObjectId(campId),
    participantEmail: email,
  });

  if (!registration) return null;
  if (registration.paymentStatus === 'Paid') return { cannotCancel: true };

  await registrationsCollection.deleteOne({ _id: registration._id });
  await campsCollection.updateOne(
    { _id: new ObjectId(campId) },
    { $inc: { participantCount: -1 } }
  );

  return { success: true };
};

const getParticipantAnalyticsInDB = async (email) => {
  const { registrationsCollection } = getCollections();
  return await registrationsCollection
    .aggregate([
      {
        $match: {
          participantEmail: email,
          paymentStatus: 'Paid',
        },
      },
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
          _id: 0,
          campName: '$camp.name',
          date: '$camp.dateTime',
          fees: '$camp.fees',
          status: '$confirmationStatus',
          paymentDate: 1,
        },
      },
      { $sort: { paymentDate: -1 } },
    ])
    .toArray();
};

module.exports = {
  registerForCampInDB,
  checkRegistrationInDB,
  deleteRegistrationInDB,
  findAllRegistrationsInDB,
  cancelRegistrationInDB,
  getParticipantAnalyticsInDB,
};
