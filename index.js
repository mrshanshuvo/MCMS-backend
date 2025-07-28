require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();
app.use(cors());
app.use(express.json());

const decodedBase64Key = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decodedBase64Key);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.ezlz7xu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();

    const db = client.db("medicalDB");
    const usersCollection = db.collection("users");
    // routes
    // POST: User
    app.post("/users", async (req, res) => {
      const { email, name, photoURL, role, created_at, last_login } = req.body;

      // Basic validation
      if (!email || !name) {
        return res.status(400).json({ error: "Email and name are required." });
      }

      const updateDoc = {
        $setOnInsert: {
          name,
          photoURL,
          role,
          created_at,
        },
        $set: {
          last_login,
        },
      };

      try {
        const result = await usersCollection.updateOne(
          { email },
          updateDoc,
          { upsert: true }
        );
        res.send(result);
      } catch (error) {
        res.status(500).json({ error: "Failed to upsert user." });
      }
    });


    // Start Express server after DB connection is ready
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("MongoDB connection error:", error);
  }
}
run().catch(console.error);

