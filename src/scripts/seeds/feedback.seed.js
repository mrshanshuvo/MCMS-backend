function getFeedbackSeedData(seededCamps, participantsList) {
  return [
    {
      campId: seededCamps[0]._id,
      participantEmail: participantsList[0].email,
      participantName: participantsList[0].name,
      participantPhotoURL: participantsList[0].photoURL,
      rating: 5,
      feedback:
        'Outstanding cardiology checkup! The doctors were extremely patient and explained my ECG results clearly.',
      date: new Date('2026-08-05'),
    },
    {
      campId: seededCamps[0]._id,
      participantEmail: participantsList[1].email,
      participantName: participantsList[1].name,
      participantPhotoURL: participantsList[1].photoURL,
      rating: 5,
      feedback: 'Very well organized medical camp. The queue moved quickly and staff were helpful.',
      date: new Date('2026-08-06'),
    },
    {
      campId: seededCamps[1]._id,
      participantEmail: participantsList[0].email,
      participantName: participantsList[0].name,
      participantPhotoURL: participantsList[0].photoURL,
      rating: 4,
      feedback:
        'Free eye care camp was fantastic. Received my prescription reading glasses right on site!',
      date: new Date('2026-08-07'),
    },
    {
      campId: seededCamps[1]._id,
      participantEmail: participantsList[4].email,
      participantName: participantsList[4].name,
      participantPhotoURL: participantsList[4].photoURL,
      rating: 5,
      feedback: 'Great vision screening. Highly recommend CareCamp events to everyone in LA.',
      date: new Date('2026-08-08'),
    },
    {
      campId: seededCamps[2]._id,
      participantEmail: participantsList[6].email,
      participantName: participantsList[6].name,
      participantPhotoURL: participantsList[6].photoURL,
      rating: 5,
      feedback:
        'Brought my kids for pediatric checkup. Dr. Maria was gentle and made the kids feel safe.',
      date: new Date('2026-08-09'),
    },
    {
      campId: seededCamps[2]._id,
      participantEmail: participantsList[7].email,
      participantName: participantsList[7].name,
      participantPhotoURL: participantsList[7].photoURL,
      rating: 4,
      feedback: 'Smooth vaccination process and comprehensive child health guide provided.',
      date: new Date('2026-08-09'),
    },
    {
      campId: seededCamps[3]._id,
      participantEmail: participantsList[0].email,
      participantName: participantsList[0].name,
      participantPhotoURL: participantsList[0].photoURL,
      rating: 5,
      feedback: 'Dental cleaning was top notch! Appreciate the complimentary dental hygiene kit.',
      date: new Date('2026-08-10'),
    },
    {
      campId: seededCamps[4]._id,
      participantEmail: participantsList[2].email,
      participantName: participantsList[2].name,
      participantPhotoURL: participantsList[2].photoURL,
      rating: 4,
      feedback:
        'Informatve orthopedic session. The joint exercises shared by Dr. Thorne really helped my knee pain.',
      date: new Date('2026-08-10'),
    },
    {
      campId: seededCamps[5]._id,
      participantEmail: participantsList[3].email,
      participantName: participantsList[3].name,
      participantPhotoURL: participantsList[3].photoURL,
      rating: 5,
      feedback:
        'HbA1c screening was quick and results were delivered immediately with diet advice.',
      date: new Date('2026-08-11'),
    },
    {
      campId: seededCamps[6]._id,
      participantEmail: participantsList[5].email,
      participantName: participantsList[5].name,
      participantPhotoURL: participantsList[5].photoURL,
      rating: 5,
      feedback:
        'Dermatologist gave great skin protection advice and recommended suitable products.',
      date: new Date('2026-08-11'),
    },
  ];
}

module.exports = { getFeedbackSeedData };
