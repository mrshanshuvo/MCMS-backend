const successStoriesData = [
  {
    title: 'Early Detection Saved My Life',
    patientName: 'Robert Vance',
    campName: 'Cardiology Health & Vitality Camp',
    story:
      'During the routine ECG check at CareCamp, doctors detected an early heart blockage. Timely intervention prevented a severe attack.',
    image: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400',
    date: '2026-07-15',
  },
  {
    title: 'Clear Vision Restored',
    patientName: 'Maria Garcia',
    campName: 'Vision & Eye Care Wellness Camp',
    story:
      'I had trouble reading for months due to cataracts. CareCamp provided free screening and arranged affordable corrective surgery.',
    image: 'https://images.unsplash.com/photo-1544005313-94ddf0286df2?w=400',
    date: '2026-07-20',
  },
  {
    title: 'Healthy Smiles for My Children',
    patientName: 'David & Family',
    campName: 'Pediatric & Dental Care Camp',
    story:
      'CareCamp dentists taught my kids proper brushing techniques and treated early cavities for free.',
    image: 'https://images.unsplash.com/photo-1491438590914-bc09fcaaf77a?w=400',
    date: '2026-07-25',
  },
  {
    title: 'Walking Without Pain Again',
    patientName: 'Eleanor Roosevelt',
    campName: 'Orthopedic Joint Care Camp',
    story:
      'Custom physiotherapy plans and knee braces provided at the camp gave me my mobility back.',
    image: 'https://images.unsplash.com/photo-1566492031773-4f4e44671857?w=400',
    date: '2026-07-28',
  },
  {
    title: 'Managing Diabetes Effortlessly',
    patientName: 'Samuel Jackson',
    campName: 'Diabetes Awareness Camp',
    story:
      'The personalized nutrition chart helped lower my HbA1c levels from 8.5 to 6.2 in three months.',
    image: 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=400',
    date: '2026-08-01',
  },
  {
    title: 'Skin Cancer Prevented',
    patientName: 'Chloe Bennett',
    campName: 'Dermatology & Skin Camp',
    story:
      'A suspicious mole identified during the skin screening was safely removed before becoming malignant.',
    image: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=400',
    date: '2026-08-03',
  },
  {
    title: 'Hearing My Grandchildren Clear Again',
    patientName: 'Arthur Pendelton',
    campName: 'ENT & Hearing Care Camp',
    story: 'Free audiology testing and subsidized hearing aid fitting transformed my daily life.',
    image: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=400',
    date: '2026-08-05',
  },
  {
    title: 'Peace of Mind for Mothers',
    patientName: 'Sophia Lin',
    campName: 'Women Wellness Camp',
    story:
      'Comprehensive gynecological checkups provided immense relief and health education for mothers.',
    image: 'https://images.unsplash.com/photo-1517841905240-472988babdf9?w=400',
    date: '2026-08-07',
  },
  {
    title: 'Recovery from Chronic Migraines',
    patientName: 'Daniel Craig',
    campName: 'Neurology Checkup Camp',
    story:
      'Neurologist consultations at CareCamp identified sleep apnoea as the root cause of my severe headaches.',
    image: 'https://images.unsplash.com/photo-1506794778202-cad84cf45f1d?w=400',
    date: '2026-08-08',
  },
  {
    title: 'Community Health Awareness Boost',
    patientName: 'Linda Thompson',
    campName: 'General Health & Vitality Camp',
    story:
      'CareCamp brought essential healthcare right to our rural neighborhood where hospital access is limited.',
    image: 'https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=400',
    date: '2026-08-10',
  },
];

const faqsData = [
  {
    question: 'How do I register for a medical camp?',
    answer:
      'Browse available camps on the homepage, click "Register Now", fill in participant details, and confirm registration.',
    category: 'Registration',
  },
  {
    question: 'Are camp registration fees refundable?',
    answer:
      'Refund requests submitted at least 48 hours prior to the camp start date are processed in full.',
    category: 'Payments',
  },
  {
    question: 'What documents should I bring to the camp?',
    answer:
      'Please bring a valid photo ID, your registration confirmation ticket, and any previous medical records.',
    category: 'General',
  },
  {
    question: 'Can I register on behalf of a family member?',
    answer:
      'Yes, you can register family members by providing their details during the registration process.',
    category: 'Registration',
  },
  {
    question: 'How do organizers post new medical camps?',
    answer:
      'Registered organizers can navigate to the Organizer Dashboard and click "Add Camp" to post camp details.',
    category: 'Organizer',
  },
  {
    question: 'What payment methods are supported for paid camps?',
    answer: 'We support all major credit/debit cards via secure Stripe payment integration.',
    category: 'Payments',
  },
  {
    question: 'Will I receive a medical summary report after the camp?',
    answer:
      'Yes, attending doctors provide digital summary reports uploaded directly to your participant profile.',
    category: 'Medical Reports',
  },
  {
    question: 'How can I submit feedback after attending a camp?',
    answer:
      'Go to your Registered Camps page and click "Feedback" to rate and review your experience.',
    category: 'Feedback',
  },
  {
    question: 'Are free camps completely free of charge?',
    answer: 'Yes, free camps require zero fee payment for consultations and basic screening tests.',
    category: 'General',
  },
  {
    question: 'How do I cancel my registration if I cannot attend?',
    answer:
      'Go to your Registered Camps dashboard and click "Cancel Registration" before the camp start date.',
    category: 'Registration',
  },
];

const blogsData = [
  {
    title: '10 Essential Heart Health Tips for Adults Over 40',
    summary:
      'Learn practical daily habits, dietary choices, and exercise routines to keep your heart healthy and resilient.',
    author: 'Dr. Robert Chen',
    category: 'Cardiology',
    image: 'https://images.unsplash.com/photo-1505751172876-fa1923c5c528?w=600',
    readTime: '5 min read',
    createdAt: '2026-08-01',
  },
  {
    title: 'Understanding Eye Strain in the Digital Age',
    summary:
      'Effective strategies to protect your vision and prevent digital eye fatigue when working long hours on screens.',
    author: 'Dr. Emily Vance',
    category: 'Ophthalmology',
    image: 'https://images.unsplash.com/photo-1584515979956-d9f6e5d09982?w=600',
    readTime: '4 min read',
    createdAt: '2026-08-02',
  },
  {
    title: 'Childhood Vaccination Schedule: A Parent Guide',
    summary:
      'A complete guide for parents explaining essential childhood vaccines, timelines, and safety guidelines.',
    author: 'Dr. Maria Rodriguez',
    category: 'Pediatrics',
    image: 'https://images.unsplash.com/photo-1581594693702-fbdc51b2763b?w=600',
    readTime: '6 min read',
    createdAt: '2026-08-03',
  },
  {
    title: 'The Golden Rules of Daily Oral Hygiene',
    summary:
      'Discover how daily flossing, proper brushing techniques, and dental checkups prevent gum disease.',
    author: 'Dr. Alan Harper',
    category: 'Dentistry',
    image: 'https://images.unsplash.com/photo-1606811841689-23dfddce3e95?w=600',
    readTime: '4 min read',
    createdAt: '2026-08-04',
  },
  {
    title: 'Preventing Joint Pain & Arthritis in Active Lifestyles',
    summary:
      'Key joint protection tips, stretching routines, and posture tips to maintain bone and mobility health.',
    author: 'Dr. James Thorne',
    category: 'Orthopedics',
    image: 'https://images.unsplash.com/photo-1579684385127-1ef15d508118?w=600',
    readTime: '5 min read',
    createdAt: '2026-08-05',
  },
  {
    title: 'Demystifying HbA1c: What Your Blood Glucose Means',
    summary:
      'Understand blood sugar metrics and learn proactive steps to manage and prevent Type 2 Diabetes.',
    author: 'Dr. Priya Sharma',
    category: 'Endocrinology',
    image: 'https://images.unsplash.com/photo-1576091160399-112ba8d25d1d?w=600',
    readTime: '7 min read',
    createdAt: '2026-08-06',
  },
  {
    title: 'Sun Protection Essentials for Healthy Skin',
    summary:
      'Dermatologist recommendations on SPF ratings, UV radiation protection, and early skin cancer screening.',
    author: 'Dr. Sophia Martinez',
    category: 'Dermatology',
    image: 'https://images.unsplash.com/photo-1629909613654-28e377c37b09?w=600',
    readTime: '4 min read',
    createdAt: '2026-08-07',
  },
  {
    title: 'Protecting Your Hearing in Loud Environments',
    summary:
      'How ambient noise affects hearing health and practical advice on using noise-canceling protection.',
    author: 'Dr. William Blake',
    category: 'ENT',
    image: 'https://images.unsplash.com/photo-1516549655169-df83a0774514?w=600',
    readTime: '5 min read',
    createdAt: '2026-08-08',
  },
  {
    title: 'Boost Brain Power: Habits for Memory & Focus',
    summary:
      'Neuroscience-backed daily exercises, nutrition, and sleep hygiene practices to sharpen memory retention.',
    author: 'Dr. Arthur Pendelton',
    category: 'Neurology',
    image: 'https://images.unsplash.com/photo-1551076805-e1869033e561?w=600',
    readTime: '6 min read',
    createdAt: '2026-08-09',
  },
  {
    title: 'Why Preventive Medical Checkups Matter Most',
    summary:
      'Why attending annual wellness camps and routine health screenings lead to longer, healthier lives.',
    author: 'Dr. Sarah Connor',
    category: 'General Health',
    image: 'https://images.unsplash.com/photo-1532938911079-1b06ac7ceec7?w=600',
    readTime: '5 min read',
    createdAt: '2026-08-10',
  },
];

module.exports = {
  successStoriesData,
  faqsData,
  blogsData,
};
