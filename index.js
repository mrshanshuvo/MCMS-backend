require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();
app.use(cors());
app.use(express.json());

// Firebase Admin Setup
const decodedBase64Key = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decodedBase64Key);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// MongoDB Connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.ezlz7xu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // await client.connect();
    const db = client.db("medicalDB");
    const usersCollection = db.collection("users");
    const campsCollection = db.collection("camps");
    const registrationsCollection = db.collection("registrations");
    const paymentsCollection = db.collection("payments");
    const feedbackCollection = db.collection("feedback");
    const successStoriesCollection = db.collection("success_stories");
    const blogCollection = db.collection("blogs");
    const faqCollection = db.collection("faq");



    // =====================
    // MIDDLEWARES START >>
    // =====================

    // Verify Firebase token
    const verifyFBToken = async (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
      }
      const token = authHeader.split(" ")[1];
      try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.user = decoded;
        next();
      } catch (error) {
        console.error("Token verification failed:", error);
        return res.status(401).json({ success: false, message: "Unauthorized" });
      }
    };

    // Verify if the user is an organizer
    const verifyOrganizer = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.user.email });
      if (user?.role !== "organizer") {
        return res.status(403).json({ success: false, message: "Organizer access required" });
      }
      next();
    };

    // Verify if the user is a participant
    const verifyParticipant = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.user.email });
      if (user?.role !== "participant") {
        return res.status(403).json({ success: false, message: "Participant access required" });
      }
      next();
    };

    // =====================
    // MIDDLEWARES END   <<
    // =====================

    // ======================
    // USER ROUTES START >>
    // ======================

    // POST: Add a new user
    app.post("/users", verifyFBToken, async (req, res) => {
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

    // PATCH: Update user's last_login
    app.patch("/users/:email", verifyFBToken, async (req, res) => {
      const email = req.params.email;
      const { last_login } = req.body;

      if (!last_login) {
        return res.status(400).json({ error: "Missing last_login value." });
      }

      try {
        const result = await usersCollection.updateOne(
          { email },
          { $set: { last_login } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "User not found" });
        }

        res.json({ success: true, message: "Last login updated", result });
      } catch (error) {
        console.error("Error updating last_login:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // GET: Get user by email
    app.get("/users/:email", async (req, res) => {
      const email = req.params.email;
      try {
        const user = await usersCollection.findOne({ email });
        if (user) {
          res.json(user);
        } else {
          res.status(404).json({ error: "User not found" });
        }
      } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).json({ error: "Failed to fetch user" });
      }
    });

    // PUT: Update user
    app.put("/users/:email", verifyFBToken, async (req, res) => {
      const email = req.params.email;
      const { name, photoURL, role } = req.body;

      const updateFields = {};
      if (name !== undefined) updateFields.name = name;
      if (photoURL !== undefined) updateFields.photoURL = photoURL;
      if (role !== undefined) updateFields.role = role;

      try {
        const updateDoc = { $set: updateFields };
        const result = await usersCollection.updateOne({ email }, updateDoc);

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "User not found" });
        }

        // Optionally fetch updated document
        const updatedUser = await usersCollection.findOne({ email });

        res.json(updatedUser);
      } catch (error) {
        console.error("Error updating user:", error);
        res.status(500).json({ error: "Failed to update user" });
      }
    });

    // GET: Get user role by email
    app.get("/users/:email/role", async (req, res) => {
      const email = req.params.email;

      try {
        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        // Default to "participant" if role not set
        res.json({ role: user.role || "participant" });
      } catch (error) {
        console.error("Error fetching user role:", error);
        res.status(500).json({ error: "Failed to fetch user role" });
      }
    });

    // ======================
    // USER ROUTES END   <<
    // ======================

    // ===========================
    // PARTICIPANT ROUTES START >>
    // ===========================

    // POST: Register for a camp (Participant only)
    app.post("/registrations", verifyFBToken, verifyParticipant, async (req, res) => {
      try {
        const { campId, participantName } = req.body;

        if (!campId) {
          return res.status(400).json({ error: "campId is required" });
        }

        const campObjectId = new ObjectId(campId);

        // Prevent duplicate registration by querying with ObjectId
        const existing = await registrationsCollection.findOne({
          campId: campObjectId,
          participantEmail: req.user.email,
        });

        if (existing) {
          return res.status(400).json({ error: "Already registered for this camp" });
        }

        const newRegistration = {
          campId: campObjectId,
          participantEmail: req.user.email,
          participantName: participantName || req.user.name || "Anonymous",
          registrationDate: new Date(),
          paymentStatus: "Unpaid",
        };

        const result = await registrationsCollection.insertOne(newRegistration);

        res.status(201).json({ success: true, registrationId: result.insertedId });
      } catch (error) {
        console.error("Error creating registration:", error);
        res.status(500).json({ error: "Failed to create registration" });
      }
    });

    // Patch: Update participant count for a camp
    app.patch("/camps/:id/increment", verifyFBToken, verifyParticipant, async (req, res) => {
      try {
        const campId = req.params.id;

        const result = await campsCollection.updateOne(
          { _id: campId },
          { $inc: { participantCount: 1 } }
        );

        if (result.modifiedCount > 0) {
          res.json({ success: true, message: "Participant count incremented" });
        } else {
          res.status(404).json({ success: false, message: "Camp not found" });
        }
      } catch (error) {
        console.error("Error updating participant count:", error);
        res.status(500).json({ error: "Failed to update participant count" });
      }
    });


    app.get("/registrations/check", verifyFBToken, async (req, res) => {
      const { campId } = req.query;
      const email = req.user.email;

      // Try both string and ObjectId versions
      const registration = await registrationsCollection.findOne({
        $or: [
          // { campId: campId, participantEmail: email },
          { campId: new ObjectId(campId), participantEmail: email }
        ]
      });

      if (registration) {
        return res.json({ registered: true });
      } else {
        return res.json({ registered: false });
      }
    });

    // GET: Get registrations by participant email
    app.get("/camps-with-registrations/:email", async (req, res) => {
      try {
        const participantEmail = req.params.email;

        const results = await campsCollection.aggregate([
          {
            $lookup: {
              from: "registrations",
              let: { campIdString: "$_id" },
              pipeline: [
                {
                  $match: {
                    $expr: {
                      $and: [
                        { $eq: [{ $toString: "$campId" }, "$$campIdString"] },
                        { $eq: ["$participantEmail", participantEmail] }
                      ]
                    }
                  }
                }
              ],
              as: "participants"
            }
          },
          {
            $match: {
              "participants.0": { $exists: true } // Only include camps where the participant has registered
            }
          },
          {
            $project: {
              _id: 1,
              name: 1,
              dateTime: 1,
              location: 1,
              fees: 1,
              healthcareProfessional: 1,
              participants: 1
            }
          }
        ]).toArray();

        res.json(results);
      } catch (error) {
        console.error("Error fetching camps by email:", error);
        res.status(500).json({
          error: "Failed to fetch camps data",
          details: error.message
        });
      }
    });

    // ==========================
    // PARTICIPANT ROUTES END <<
    // ==========================

    // ======================
    // CAMP ROUTES START >>
    // ======================

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

    // POST: Add a new camp (Organizer only)
    app.post("/camps", verifyFBToken, verifyOrganizer, async (req, res) => {
      try {
        const newCamp = req.body;
        newCamp.organizerEmail = req.user.email;
        // Add default values
        newCamp.participantCount = 0;
        newCamp.createdAt = new Date();

        const result = await campsCollection.insertOne(newCamp);
        res.status(201).json({ success: true, message: "Camp added", campId: result.insertedId });
      } catch (error) {
        console.error("Error adding camp:", error);
        res.status(500).json({ success: false, error: "Failed to add camp" });
      }
    });

    // GET: Get camps by organizer email
    app.get("/organizer/camps", verifyFBToken, verifyOrganizer, async (req, res) => {
      try {
        const organizerEmail = req.user.email;
        const organizerCamps = await campsCollection.find({ organizerEmail }).toArray();
        res.json(organizerCamps);
      } catch (error) {
        console.error("Error fetching organizer camps:", error);
        res.status(500).json({ error: "Failed to fetch organizer camps" });
      }
    });

    // ======================
    // CAMP ROUTES END <<
    // ======================

    // =========================================
    // UPDATED CAMP ROUTES (ORGANIZER) START >>
    // =========================================

    // PATCH: Update camp by ID (Organizer only) - using expected endpoint
    app.patch("/update-camp/:campId", verifyFBToken, verifyOrganizer, async (req, res) => {
      try {
        const campId = req.params.campId;
        const updatedCamp = req.body;

        // Verify the camp belongs to the organizer
        const camp = await campsCollection.findOne({
          _id: new ObjectId(campId),
          organizerEmail: req.user.email
        });

        if (!camp) {
          return res.status(404).json({
            success: false,
            message: "Camp not found or not owned by organizer"
          });
        }

        const result = await campsCollection.updateOne(
          { _id: new ObjectId(campId) },
          { $set: updatedCamp }
        );

        if (result.modifiedCount > 0) {
          res.json({ success: true });
        } else {
          res.json({ success: false, message: "Camp not found or no changes" });
        }
      } catch (error) {
        console.error("Error updating camp:", error);
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // DELETE: Delete camp by ID (Organizer only) - using expected endpoint and adding ownership check
    app.delete('/delete-camp/:campId', verifyFBToken, verifyOrganizer, async (req, res) => {
      try {
        const campId = req.params.campId;

        // First verify the camp belongs to this organizer
        const camp = await campsCollection.findOne({
          _id: new ObjectId(campId),
          organizerEmail: req.user.email
        });

        if (!camp) {
          return res.status(404).json({
            success: false,
            message: "Camp not found or not owned by organizer"
          });
        }

        // Delete the camp
        const result = await campsCollection.deleteOne({
          _id: new ObjectId(campId)
        });

        if (result.deletedCount > 0) {
          // Also delete related registrations
          await registrationsCollection.deleteMany({
            campId: new ObjectId(campId)
          });

          res.json({
            success: true,
            deletedCount: result.deletedCount
          });
        } else {
          res.status(404).json({
            success: false,
            message: "Camp not found"
          });
        }
      } catch (error) {
        console.error("Error deleting camp:", error);
        res.status(500).json({
          success: false,
          error: 'Failed to delete camp',
          details: error.message
        });
      }
    });

    // =========================================
    // UPDATED CAMP ROUTES (ORGANIZER) END   <<
    // =========================================

    // ========================
    // PAYMENT ROUTES START >>
    // ========================

    // GET /payments?email=someone@example.com
    app.get("/payments", verifyFBToken, async (req, res) => {
      try {
        const email = req.query.email;

        if (!email) {
          return res.status(400).send({
            success: false,
            message: "Email query parameter required",
          });
        }

        if (req.user.email !== email) {
          return res.status(403).send({
            success: false,
            message: "Unauthorized",
          });
        }

        const payments = await paymentsCollection
          .find({ participantEmail: email })
          .sort({ payment_time: -1 })
          .toArray();

        res.send({ success: true, data: payments });
      } catch (error) {
        console.error("Error fetching payments:", error);
        res.status(500).send({
          success: false,
          message: "Failed to fetch payment history",
        });
      }
    });

    app.post("/create-payment-intent", verifyFBToken, verifyParticipant, async (req, res) => {
      const { amount, campId } = req.body;

      try {
        const paymentIntent = await stripe.paymentIntents.create({
          amount: amount * 100, // amount in cents
          currency: "usd",
          metadata: { campId },
        });

        res.send({
          clientSecret: paymentIntent.client_secret,
        });
      } catch (err) {
        console.error("Error creating payment intent:", err);
        res.status(500).send({ error: err.message });
      }
    });

    // POST: Save payment and update registration status
    app.post("/payments", verifyFBToken, async (req, res) => {
      const session = client.startSession();

      try {
        const {
          campId,
          registrationId,
          transactionId,
          amount,
          paymentMethod
        } = req.body;

        // Validate required fields
        if (!campId || !registrationId || !transactionId || !amount) {
          return res.status(400).json({
            success: false,
            message: "Missing required payment information"
          });
        }

        // Verify registration belongs to user
        const registration = await registrationsCollection.findOne({
          _id: new ObjectId(registrationId),
          participantEmail: req.user.email
        }, { session });

        if (!registration) {
          return res.status(404).json({
            success: false,
            message: "Registration not found or not owned by user"
          });
        }

        // Check for duplicate payment
        const existingPayment = await paymentsCollection.findOne({
          registrationId: new ObjectId(registrationId)
        }, { session });

        if (existingPayment) {
          return res.status(400).json({
            success: false,
            message: "Payment already processed for this registration"
          });
        }

        await session.withTransaction(async () => {
          // 1. Update the registration's payment status
          const registrationUpdate = await registrationsCollection.updateOne(
            { _id: new ObjectId(registrationId) },
            { $set: { paymentStatus: "Paid" } },
            { session }
          );

          // 2. Create payment record
          const paymentRecord = {
            campId: new ObjectId(campId),
            registrationId: new ObjectId(registrationId),
            participantEmail: req.user.email,
            transactionId,
            amount: amount / 100, // Convert back to dollars
            paymentMethod,
            paymentDate: new Date(),
            status: "Completed"
          };

          const paymentInsert = await paymentsCollection.insertOne(
            paymentRecord,
            { session }
          );
        });

        res.json({
          success: true,
          message: "Payment processed successfully"
        });
      } catch (error) {
        console.error("Payment processing error:", {
          error: error.message,
          stack: error.stack,
          requestBody: req.body,
          user: req.user.email
        });
        res.status(500).json({
          success: false,
          message: "Failed to process payment"
        });
      } finally {
        await session.endSession();
      }
    });

    // ========================
    // PAYMENT ROUTES END   <<
    // ========================

    // ==============================
    // STATIC PUBLIC ROUTES START >>
    // ==============================

    // GET /successStories
    app.get("/successStories", async (req, res) => {
      try {
        const successStories = await successStoriesCollection.find().toArray();
        res.send({ success: true, data: successStories });
      } catch (error) {
        console.error("Error fetching success stories:", error);
        res.status(500).send({
          success: false,
          message: "Failed to fetch success stories",
        });
      }
    })

    // GET /faq
    app.get("/faqs", async (req, res) => {
      try {
        const faq = await faqCollection.find().toArray();
        res.send({ success: true, data: faq });
      } catch (error) {
        console.error("Error fetching faq:", error);
        res.status(500).send({
          success: false,
          message: "Failed to fetch faq",
        });
      }
    })

    // GET /blogs
    app.get("/blogs", async (req, res) => {
      try {
        const blog = await blogCollection.find().toArray();
        res.send({ success: true, data: blog });
      } catch (error) {
        console.error("Error fetching blog:", error);
        res.status(500).send({
          success: false,
          message: "Failed to fetch blog",
        });
      }
    })

    // ============================
    // STATIC PUBLIC ROUTES END <<
    // ============================

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

