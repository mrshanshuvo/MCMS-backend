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
    const campsCollection = db.collection("camps");

    // routes

    // POST: Add a new user
    app.post("/users", async (req, res) => {
      const { email, name, photoURL, role, created_at, last_login } = req.body;

      // Basic validation
      if (!email) {
        return res.status(400).json({ error: "Email is required." });
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

    // GET: Camps list with search, sort, pagination
    app.get("/camps", async (req, res) => {
      try {
        const {
          search = "",
          sort = "participantCount",
          page = "1",
          limit = "6",
        } = req.query;

        const pageNum = parseInt(page, 10);
        const limitNum = parseInt(limit, 10);

        const searchRegex = new RegExp(search, "i");

        const query = {
          $or: [
            { campName: { $regex: searchRegex } },
            { location: { $regex: searchRegex } },
            { healthcareProfessional: { $regex: searchRegex } },
          ],
        };

        let sortOption = {};
        switch (sort) {
          case "participantCount":
            sortOption = { participantCount: -1 };
            break;
          case "campFeesAsc":
            sortOption = { campFees: 1 };
            break;
          case "campFeesDesc":
            sortOption = { campFees: -1 };
            break;
          case "alphabetical":
            sortOption = { campName: 1 };
            break;
          default:
            sortOption = { participantCount: -1 };
        }

        const total = await campsCollection.countDocuments(query);

        const camps = await campsCollection
          .find(query)
          .sort(sortOption)
          .skip((pageNum - 1) * limitNum)
          .limit(limitNum)
          .toArray();

        res.json({
          total,
          page: pageNum,
          limit: limitNum,
          totalPages: Math.ceil(total / limitNum),
          camps,
        });
      } catch (error) {
        console.error("Error fetching camps:", error);
        res.status(500).json({ error: "Server error" });
      }
    });

    // GET: Get camp by ID
    app.get("/camps/:id", async (req, res) => {
      try {
        const campId = req.params.id;

        if (!campId) {
          return res.status(400).json({ error: "Camp ID is required" });
        }

        // Query by string _id
        const camp = await campsCollection.findOne({ _id: campId });

        if (!camp) {
          return res.status(404).json({ error: "Camp not found" });
        }

        res.json({ camp });
      } catch (error) {
        console.error("Error fetching camp by ID:", error);
        res.status(500).json({ error: "Server error" });
      }
    });



    // Start Express server after DB connection is ready
    const PORT = process.env.PORT || 5000;
    app.get("/", (req, res) => {
      res.send("Medical Camp Management System Backend is Running");
    });

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("MongoDB connection error:", error);
  }
}
run().catch(console.error);

