const { ObjectId } = require('mongodb');
const { Parser } = require('json2csv');
const { getCollections } = require('../../config/db');

const getOrganizerOverviewInDB = async (organizerEmail) => {
  const { campsCollection, registrationsCollection, paymentsCollection } = getCollections();

  const organizerCamps = await campsCollection.find({ organizerEmail }).toArray();
  const campIds = organizerCamps.map((c) => c._id);

  const [totalRegistrations, paidPayments, monthlyRevenue] = await Promise.all([
    registrationsCollection.countDocuments({ campId: { $in: campIds } }),
    paymentsCollection
      .aggregate([
        { $match: { campId: { $in: campIds }, status: 'Completed' } },
        { $group: { _id: null, totalRevenue: { $sum: '$amount' }, count: { $sum: 1 } } },
      ])
      .toArray(),
    paymentsCollection
      .aggregate([
        { $match: { campId: { $in: campIds }, status: 'Completed' } },
        {
          $group: {
            _id: {
              year: { $year: '$paymentDate' },
              month: { $month: '$paymentDate' },
            },
            revenue: { $sum: '$amount' },
            count: { $sum: 1 },
          },
        },
        { $sort: { '_id.year': -1, '_id.month': -1 } },
      ])
      .toArray(),
  ]);

  const totalRevenue = paidPayments[0]?.totalRevenue || 0;
  const paidCount = paidPayments[0]?.count || 0;

  return {
    summary: {
      totalCamps: organizerCamps.length,
      totalRegistrations,
      paidCount,
      totalRevenue,
    },
    monthlyRevenue: monthlyRevenue.map((item) => ({
      year: item._id.year,
      month: item._id.month,
      revenue: item.revenue,
      transactions: item.count,
    })),
    campsBreakdown: organizerCamps.map((camp) => ({
      campId: camp._id,
      campName: camp.name || camp.campName,
      participantCount: camp.participantCount || 0,
      fees: camp.fees || 0,
    })),
  };
};

const exportRegistrationsCSVInDB = async (organizerEmail, campId) => {
  const { campsCollection, registrationsCollection } = getCollections();

  const query = { organizerEmail };
  if (campId && ObjectId.isValid(campId)) {
    query._id = new ObjectId(campId);
  }

  const organizerCamps = await campsCollection.find(query).toArray();
  const campIds = organizerCamps.map((c) => c._id);
  const campMap = organizerCamps.reduce((acc, c) => {
    acc[c._id.toString()] = c.name || c.campName;
    return acc;
  }, {});

  const registrations = await registrationsCollection
    .find({ campId: { $in: campIds } })
    .sort({ registrationDate: -1 })
    .toArray();

  const formattedData = registrations.map((r) => ({
    Registration_ID: r._id.toString(),
    Camp_Name: campMap[r.campId?.toString()] || 'N/A',
    Participant_Name: r.participantName,
    Participant_Email: r.participantEmail,
    Age: r.age,
    Phone: r.phoneNumber,
    Gender: r.gender,
    Emergency_Contact: r.emergencyContact,
    Payment_Status: r.paymentStatus,
    Confirmation_Status: r.confirmationStatus,
    Registration_Date: r.registrationDate ? new Date(r.registrationDate).toISOString() : '',
  }));

  const fields = [
    'Registration_ID',
    'Camp_Name',
    'Participant_Name',
    'Participant_Email',
    'Age',
    'Phone',
    'Gender',
    'Emergency_Contact',
    'Payment_Status',
    'Confirmation_Status',
    'Registration_Date',
  ];

  const json2csvParser = new Parser({ fields });
  return json2csvParser.parse(formattedData);
};

const exportPaymentsCSVInDB = async (organizerEmail) => {
  const { campsCollection, paymentsCollection } = getCollections();

  const organizerCamps = await campsCollection.find({ organizerEmail }).toArray();
  const campIds = organizerCamps.map((c) => c._id);
  const campMap = organizerCamps.reduce((acc, c) => {
    acc[c._id.toString()] = c.name || c.campName;
    return acc;
  }, {});

  const payments = await paymentsCollection
    .find({ campId: { $in: campIds } })
    .sort({ paymentDate: -1 })
    .toArray();

  const formattedData = payments.map((p) => ({
    Payment_ID: p._id.toString(),
    Camp_Name: campMap[p.campId?.toString()] || 'N/A',
    Participant_Email: p.participantEmail,
    Transaction_ID: p.transactionId,
    Amount_USD: p.amount,
    Payment_Method: p.paymentMethod || 'Stripe',
    Status: p.status,
    Payment_Date: p.paymentDate ? new Date(p.paymentDate).toISOString() : '',
  }));

  const fields = [
    'Payment_ID',
    'Camp_Name',
    'Participant_Email',
    'Transaction_ID',
    'Amount_USD',
    'Payment_Method',
    'Status',
    'Payment_Date',
  ];

  const json2csvParser = new Parser({ fields });
  return json2csvParser.parse(formattedData);
};

module.exports = {
  getOrganizerOverviewInDB,
  exportRegistrationsCSVInDB,
  exportPaymentsCSVInDB,
};
