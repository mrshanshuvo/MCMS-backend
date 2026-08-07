const admin = require('firebase-admin');

const decodedBase64Key = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decodedBase64Key);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

module.exports = admin;
