require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");


const app = express();
app.use(cors());
app.use(express.json());

// Firebase Admin Setup
const decodedBase64Key = Buffer.from(
  process.env.FB_SERVICE_KEY,
  "base64"
).toString("utf8");
const serviceAccount = JSON.parse(decodedBase64Key);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Middleware
app.use(cors(
  {
    origin: ["https://mcms-auth.web.app"],
    credentials: true
  }
));

// Right after app initialization (before routes)
app.use(helmet());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests
}));

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
    const db = client.db("medicalDB");
    const usersCollection = db.collection("users");
    const campsCollection = db.collection("camps");
    const registrationsCollection = db.collection("registrations");
    const paymentsCollection = db.collection("payments");
    const feedbackCollection = db.collection("feedback");
    const successStoriesCollection = db.collection("success_stories");
    const blogCollection = db.collection("blogs");
    const faqCollection = db.collection("faq");

    // Add this after your collection declarations in the run() function
    await registrationsCollection.createIndex({ participantEmail: 1 });
    await registrationsCollection.createIndex({ campId: 1 });
    await registrationsCollection.createIndex(
      { transactionId: 1 },
      { unique: true }
    );
    await feedbackCollection.createIndex({ campId: 1 });
    await feedbackCollection.createIndex({ participantEmail: 1 });

    // =====================
    // MIDDLEWARES START >>
    // =====================

    const verifyFBToken = async (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res
          .status(401)
          .json({ success: false, message: "Unauthorized" });
      }
      const token = authHeader.split(" ")[1];
      try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.user = decoded;
        next();
      } catch (error) {
        console.error("Token verification failed:", error);
        return res
          .status(401)
          .json({ success: false, message: "Unauthorized" });
      }
    };

    const verifyOrganizer = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.user.email });
      if (user?.role !== "organizer") {
        return res
          .status(403)
          .json({ success: false, message: "Organizer access required" });
      }
      next();
    };

    const verifyParticipant = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.user.email });
      if (user?.role !== "participant") {
        return res
          .status(403)
          .json({ success: false, message: "Participant access required" });
      }
      next();
    };

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
        const result = await usersCollection.updateOne({ email }, updateDoc, {
          upsert: true,
        });
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
      const { name, photoURL, role, phone, address } = req.body;

      const updateFields = {};
      if (name !== undefined) updateFields.name = name;
      if (photoURL !== undefined) updateFields.photoURL = photoURL;
      if (role !== undefined) updateFields.role = role;
      if (phone !== undefined) updateFields.phone = phone;
      if (address !== undefined) updateFields.address = address;

      try {
        const updateDoc = { $set: updateFields };
        const result = await usersCollection.updateOne({ email }, updateDoc);

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "User not found" });
        }

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

    // ===========================
    // PARTICIPANT ROUTES START >>
    // ===========================

    // POST: Register for a camp
    app.post(
      "/registrations",
      verifyFBToken,
      verifyParticipant,
      async (req, res) => {
        try {
          const {
            campId,
            participantName,
            participantEmail,
            age,
            phoneNumber,
            gender,
            emergencyContact,
          } = req.body;

          // Validate required fields
          if (
            !campId ||
            !participantEmail ||
            !age ||
            !phoneNumber ||
            !gender ||
            !emergencyContact
          ) {
            return res.status(400).json({ error: "Missing required fields" });
          }

          // Check if campId is valid
          if (!ObjectId.isValid(campId)) {
            return res.status(400).json({ error: "Invalid campId format" });
          }

          // Check for existing registration
          const existing = await registrationsCollection.findOne({
            campId: new ObjectId(campId),
            participantEmail,
          });

          if (existing) {
            return res
              .status(400)
              .json({ error: "Already registered for this camp" });
          }

          // Create new registration with a unique transactionId
          const newRegistration = {
            campId: new ObjectId(campId),
            participantEmail,
            participantName: participantName || "Anonymous",
            age: parseInt(age),
            phoneNumber,
            gender,
            emergencyContact,
            registrationDate: new Date(),
            paymentStatus: "Unpaid",
            confirmationStatus: "Pending",
            transactionId: new ObjectId(), // Generate a unique ID
          };

          const result = await registrationsCollection.insertOne(
            newRegistration
          );
          res
            .status(201)
            .json({ success: true, registrationId: result.insertedId });
        } catch (error) {
          console.error("Registration Error:", error);
          if (error.code === 11000) {
            return res
              .status(400)
              .json({ error: "Duplicate registration detected" });
          }
          res
            .status(500)
            .json({ error: "Registration failed", details: error.message });
        }
      }
    );
    // GET: Check if registered for camp
    app.get("/registrations/check", verifyFBToken, async (req, res) => {
      try {
        const { campId } = req.query;
        const registration = await registrationsCollection.findOne({
          campId: new ObjectId(campId),
          participantEmail: req.user.email,
        });
        res.json({ registered: !!registration });
      } catch (error) {
        console.error("Error checking registration:", error);
        res.status(500).json({ error: "Failed to check registration" });
      }
    });

    // DELETE a registration by ID
    app.delete("/registrations/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const result = await registrationsCollection.deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 0) {
          return res.status(404).json({ message: "Registration not found" });
        }

        res.json({ message: "Registration deleted successfully" });
      } catch (error) {
        console.error("Error deleting registration:", error);
        res.status(500).json({ error: "Server error" });
      }
    });


    // GET: Get registered camps with details
    app.get(
      "/camps-with-registrations/:email",
      verifyFBToken,
      verifyParticipant,
      async (req, res) => {
        try {
          const page = parseInt(req.query.page) || 1;
          const limit = parseInt(req.query.limit) || 5;
          const skip = (page - 1) * limit;

          const [results, total] = await Promise.all([
            campsCollection
              .aggregate([
                {
                  $lookup: {
                    from: "registrations",
                    let: { campIdObj: "$_id" },
                    pipeline: [
                      {
                        $match: {
                          $expr: {
                            $and: [
                              { $eq: ["$campId", "$$campIdObj"] },
                              { $eq: ["$participantEmail", req.params.email] },
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
                    as: "participants",
                  },
                },
                { $match: { "participants.0": { $exists: true } } },
                {
                  $lookup: {
                    from: "feedback",
                    let: { campIdObj: "$_id" },
                    pipeline: [
                      {
                        $match: {
                          $expr: {
                            $and: [
                              { $eq: ["$campId", "$$campIdObj"] },
                              { $eq: ["$participantEmail", req.params.email] },
                            ],
                          },
                        },
                      },
                      { $limit: 1 },
                    ],
                    as: "userFeedback",
                  },
                },
                {
                  $addFields: {
                    hasFeedback: { $gt: [{ $size: "$userFeedback" }, 0] },
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
                    from: "registrations",
                    let: { campIdObj: "$_id" },
                    pipeline: [
                      {
                        $match: {
                          $expr: {
                            $and: [
                              { $eq: ["$campId", "$$campIdObj"] },
                              { $eq: ["$participantEmail", req.params.email] },
                            ],
                          },
                        },
                      },
                    ],
                    as: "participants",
                  },
                },
                { $match: { "participants.0": { $exists: true } } },
                { $count: "total" },
              ])
              .toArray(),
          ]);

          const totalCount = total[0]?.total || 0;

          res.json({ results, totalCount });
        } catch (error) {
          console.error("Error fetching camps:", error);
          res.status(500).json({ error: "Failed to fetch camps data" });
        }
      }
    );

    // Add with other routes
    app.get('/analytics/:participantId', verifyFBToken, async (req, res) => {
      try {
        const analytics = await registrationsCollection.aggregate([
          {
            $match: {
              participantEmail: req.user.email,
              paymentStatus: "Paid"
            }
          },
          {
            $lookup: {
              from: "camps",
              localField: "campId",
              foreignField: "_id",
              as: "camp"
            }
          },
          { $unwind: "$camp" },
          {
            $project: {
              _id: 0,
              campName: "$camp.name",
              date: "$camp.dateTime",
              fees: "$camp.fees",
              status: "$confirmationStatus",
              paymentDate: 1
            }
          },
          { $sort: { paymentDate: -1 } }
        ]).toArray();

        res.json({
          success: true,
          data: analytics
        });
      } catch (error) {
        console.error("Analytics error:", error);
        res.status(500).json({
          success: false,
          error: "Failed to fetch analytics"
        });
      }
    });

    // PATCH: Increment participant count for a camp
    app.patch("/camps/:id/increment", verifyFBToken, async (req, res) => {
      try {
        const campId = req.params.id;

        if (!ObjectId.isValid(campId)) {
          return res.status(400).json({ error: "Invalid camp ID format" });
        }

        const result = await campsCollection.updateOne(
          { _id: new ObjectId(campId) },
          { $inc: { participantCount: 1 } }
        );

        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .json({ error: "Camp not found or count not updated" });
        }

        res.status(200).json({ success: true });
      } catch (error) {
        console.error("Increment Error:", error);
        res.status(500).json({ error: "Failed to increment count" });
      }
    });

    // ========================
    // PAYMENT ROUTES START >>
    // ========================

    // POST: Create payment intent
    app.post(
      "/create-payment-intent",
      verifyFBToken,
      verifyParticipant,
      async (req, res) => {
        try {
          const { amount, campId } = req.body;
          if (amount === 0) {
            return res.json({ clientSecret: null });
          }
          const paymentIntent = await stripe.paymentIntents.create({
            amount: amount * 100,
            currency: "usd",
            metadata: { campId, participantEmail: req.user.email },
          });
          res.json({ clientSecret: paymentIntent.client_secret });
        } catch (error) {
          console.error("Payment intent error:", error);
          res.status(500).json({ error: "Failed to create payment intent" });
        }
      }
    );

    // POST: Process payment
    app.post("/payments", verifyFBToken, async (req, res) => {
      const session = client.startSession();
      try {
        const { campId, registrationId, transactionId, amount, paymentMethod } =
          req.body;
        console.log("Incoming payment:", { campId, registrationId, transactionId, amount, paymentMethod });

        await session.withTransaction(async () => {
          // Verify registration
          const registration = await registrationsCollection.findOne(
            {
              _id: new ObjectId(registrationId),
              participantEmail: req.user.email,
            },
            { session }
          );

          if (!registration) throw new Error("Registration not found");
          if (registration.paymentStatus === "Paid")
            throw new Error("Payment already processed");

          // Update registration
          await registrationsCollection.updateOne(
            { _id: registration._id },
            {
              $set: {
                paymentStatus: "Paid",
                confirmationStatus: "Confirmed",
                transactionId,
              },
            },
            { session }
          );

          // Create payment record
          await paymentsCollection.insertOne(
            {
              campId: new ObjectId(campId),
              registrationId: new ObjectId(registrationId),
              participantEmail: req.user.email,
              transactionId,
              amount: amount,
              paymentMethod,
              paymentDate: new Date(),
              status: "Completed",
            },
            { session }
          );
        });

        res.json({ success: true });
      } catch (error) {
        console.error("Payment processing error:", error);
        console.error("Payment error stack:", error.stack);
        res.status(500).json({ error: error.message });

      } finally {
        await session.endSession();
      }
    });

    // GET: Payment history
    app.get("/payments", verifyFBToken, async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 5;
        const skip = (page - 1) * limit;

        const query = { participantEmail: req.user.email };

        const total = await paymentsCollection.countDocuments(query);

        const payments = await paymentsCollection
          .find(query)
          .sort({ paymentDate: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.json({
          data: payments,
          pagination: {
            total,
            page,
            limit,
            totalPages: Math.ceil(total / limit),
          },
        });
      } catch (error) {
        console.error("Error fetching paginated payments:", error);
        res.status(500).json({ error: "Failed to fetch payments" });
      }
    });


    // GET: Payment history by email query param
    app.get("/paymentsByEmail", verifyFBToken, async (req, res) => {
      try {
        const email = req.query.email;

        if (req.user.email !== email)
          return res.status(403).send({
            success: false,
            message: "Unauthorized",
          });

        const filter = email ? { participantEmail: email } : {};

        const payments = await paymentsCollection
          .find(filter)
          .sort({ payment_time: -1 }) // latest first
          .toArray();

        res.send({ success: true, data: payments });
      } catch (error) {
        console.error("Error fetching payments:", error);
        res
          .status(500)
          .send({ success: false, message: "Failed to fetch payment history" });
      }
    });

    // Stripe webhook
    app.post(
      "/stripe-webhook",
      express.raw({ type: "application/json" }),
      async (req, res) => {
        const sig = req.headers["stripe-signature"];
        let event;

        try {
          event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET
          );
        } catch (err) {
          console.error("Webhook error:", err);
          return res.status(400).send(`Webhook Error: ${err.message}`);
        }

        if (event.type === "payment_intent.succeeded") {
          const paymentIntent = event.data.object;
          const { campId, participantEmail } = paymentIntent.metadata;

          try {
            await registrationsCollection.updateOne(
              {
                campId: new ObjectId(campId),
                participantEmail,
                transactionId: paymentIntent.id,
              },
              {
                $set: {
                  paymentStatus: "Paid",
                  confirmationStatus: "Confirmed",
                },
              }
            );
          } catch (error) {
            console.error("Webhook update error:", error);
          }
        }

        res.json({ received: true });
      }
    );

    // ======================
    // FEEDBACK ROUTES START >>
    // ======================

    // POST: Submit feedback
    app.post("/feedback", verifyFBToken, async (req, res) => {
      try {
        const { campId, rating, feedback, name, photoURL } = req.body;

        if (rating < 1 || rating > 5) {
          return res.status(400).json({ error: "Rating must be between 1-5" });
        }

        // Verify camp attendance
        const registration = await registrationsCollection.findOne({
          campId: new ObjectId(campId),
          participantEmail: req.user.email,
          paymentStatus: "Paid",
        });

        if (!registration) {
          return res
            .status(403)
            .json({ error: "You must attend the camp to provide feedback" });
        }

        // Check for existing feedback
        const existing = await feedbackCollection.findOne({
          campId: new ObjectId(campId),
          participantEmail: req.user.email,
        });

        if (existing) {
          return res.status(400).json({ error: "Feedback already submitted" });
        }

        // Create feedback
        await feedbackCollection.insertOne({
          campId: new ObjectId(campId),
          participantEmail: req.user.email,
          participantName: name || "Anonymous",
          participantPhotoURL: photoURL,
          rating,
          feedback,
          date: new Date(),
        });

        res.status(201).json({ success: true });
      } catch (error) {
        console.error("Feedback error:", error);
        res.status(500).json({ error: "Failed to submit feedback" });
      }
    });

    // GET: Recent feedback for home page
    app.get("/feedback", async (req, res) => {
      try {
        const limit = parseInt(req.query.limit) || 5;
        const feedback = await feedbackCollection
          .aggregate([
            {
              $lookup: {
                from: "camps",
                localField: "campId",
                foreignField: "_id",
                as: "camp",
              },
            },
            { $unwind: "$camp" },
            {
              $project: {
                _id: 1,
                rating: 1,
                feedback: 1,
                date: 1,
                participantName: 1,
                participantPhotoURL: 1,
                campName: "$camp.name",
              },
            },
            { $sort: { date: -1 } },
            { $limit: limit },
          ])
          .toArray();

        res.json(feedback);
      } catch (error) {
        console.error("Feedback fetch error:", error);
        res.status(500).json({ error: "Failed to fetch feedback" });
      }
    });

    // ======================
    // CAMP ROUTES START >>
    // ======================

    // GET: Get all registrations
    app.get("/registrations", verifyFBToken, verifyOrganizer, async (req, res) => {
      try {
        // Parse query parameters
        const {
          page = 1,
          limit = 10,
          search = '',
          status = 'all',
          campId,
          sortBy = 'registrationDate',
          sortOrder = 'desc'
        } = req.query;

        // Validate and sanitize inputs
        const pageNumber = Math.max(parseInt(page), 1);
        const limitNumber = Math.min(Math.max(parseInt(limit), 1), 100);
        const sortDirection = sortOrder === 'asc' ? 1 : -1;

        // Build the query filter
        const filter = {};

        // Status filter
        if (status !== 'all') {
          filter.status = status;
        }

        // Camp ID filter
        if (campId) {
          filter.campId = new ObjectId(campId);
        }

        // Search filter (case-insensitive)
        if (search) {
          const searchRegex = new RegExp(search, 'i');
          filter.$or = [
            { participantName: searchRegex },
            { participantEmail: searchRegex },
            { transactionId: searchRegex }
          ];
        }

        // Get total count for pagination
        const totalCount = await registrationsCollection.countDocuments(filter);

        // Fetch paginated and sorted registrations
        const registrations = await registrationsCollection
          .find(filter)
          .sort({ [sortBy]: sortDirection })
          .skip((pageNumber - 1) * limitNumber)
          .limit(limitNumber)
          .toArray();

        // Populate camp information if needed
        const campIds = [...new Set(registrations.map(r => r.campId))];
        const camps = await campsCollection.find({
          _id: { $in: campIds }
        }).toArray();

        const campMap = camps.reduce((map, camp) => {
          map[camp._id] = camp;
          return map;
        }, {});

        const enrichedRegistrations = registrations.map(reg => ({
          ...reg,
          campName: campMap[reg.campId]?.name || 'Unknown Camp',
          campFees: campMap[reg.campId]?.fees || 0,
          campLocation: campMap[reg.campId]?.location || 'Unknown Location'
        }));

        res.status(200).json({
          success: true,
          data: enrichedRegistrations,
          pagination: {
            page: pageNumber,
            limit: limitNumber,
            totalCount,
            totalPages: Math.ceil(totalCount / limitNumber)
          }
        });

      } catch (error) {
        console.error("Failed to get registrations:", error);
        res.status(500).json({
          success: false,
          error: "Failed to fetch registrations",
          details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
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

        const objectId = new ObjectId(campId); // FIX HERE
        const camp = await campsCollection.findOne({ _id: objectId });

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
        res
          .status(201)
          .json({
            success: true,
            message: "Camp added",
            campId: result.insertedId,
          });
      } catch (error) {
        console.error("Error adding camp:", error);
        res.status(500).json({ success: false, error: "Failed to add camp" });
      }
    });

    // GET: Get paginated camps by organizer email
    app.get(
      "/organizer/camps",
      verifyFBToken,
      verifyOrganizer,
      async (req, res) => {
        try {
          const organizerEmail = req.user.email;
          const page = parseInt(req.query.page) || 1;
          const limit = parseInt(req.query.limit) || 5;
          const skip = (page - 1) * limit;

          const query = { organizerEmail };

          const camps = await campsCollection.find(query)
            .skip(skip)
            .limit(limit)
            .toArray();

          const totalCount = await campsCollection.countDocuments(query);

          res.json({
            camps,
            totalCount,
            currentPage: page,
            totalPages: Math.ceil(totalCount / limit),
          });
        } catch (error) {
          console.error("Error fetching organizer camps:", error);
          res.status(500).json({ error: "Failed to fetch organizer camps" });
        }
      }
    );


    // DELETE: Cancel registration (update to handle payment status)
    app.delete(
      "/cancel-registration/:campId",
      verifyFBToken,
      async (req, res) => {
        try {
          const campId = req.params.campId;
          const email = req.user.email;

          // Find the registration
          const registration = await registrationsCollection.findOne({
            campId: new ObjectId(campId),
            participantEmail: email,
          });

          if (!registration) {
            return res.status(404).json({ error: "Registration not found" });
          }

          // Check payment status
          if (registration.paymentStatus === "Paid") {
            return res.status(400).json({
              error: "Cannot cancel after payment. Please contact support.",
            });
          }

          // Delete the registration
          await registrationsCollection.deleteOne({
            _id: registration._id,
          });

          // Decrement participant count
          await campsCollection.updateOne(
            { _id: new ObjectId(campId) },
            { $inc: { participantCount: -1 } }
          );

          res.json({ success: true });
        } catch (error) {
          console.error("Error cancelling registration:", error);
          res.status(500).json({ error: "Failed to cancel registration" });
        }
      }
    );

    // =========================================
    // UPDATED CAMP ROUTES (ORGANIZER) START >>
    // =========================================

    // PATCH: Update camp by ID (Organizer only) - using expected endpoint
    app.patch(
      "/camps/:campId",
      verifyFBToken,
      verifyOrganizer,
      async (req, res) => {
        try {
          const campId = req.params.campId;
          const updatedCamp = req.body;

          // Verify the camp belongs to the organizer
          const camp = await campsCollection.findOne({
            _id: new ObjectId(campId),
            organizerEmail: req.user.email,
          });

          if (!camp) {
            return res.status(404).json({
              success: false,
              message: "Camp not found or not owned by organizer",
            });
          }

          const result = await campsCollection.updateOne(
            { _id: new ObjectId(campId) },
            { $set: updatedCamp }
          );

          if (result.modifiedCount > 0) {
            res.json({ success: true });
          } else {
            res.json({
              success: false,
              message: "Camp not found or no changes",
            });
          }
        } catch (error) {
          console.error("Error updating camp:", error);
          res.status(500).json({ success: false, error: error.message });
        }
      }
    );

    // DELETE: Delete camp by ID (Organizer only) - using expected endpoint and adding ownership check
    app.delete(
      "/delete-camp/:campId",
      verifyFBToken,
      verifyOrganizer,
      async (req, res) => {
        try {
          const campId = req.params.campId;

          // First verify the camp belongs to this organizer
          const camp = await campsCollection.findOne({
            _id: new ObjectId(campId),
            organizerEmail: req.user.email,
          });

          if (!camp) {
            return res.status(404).json({
              success: false,
              message: "Camp not found or not owned by organizer",
            });
          }

          // Delete the camp
          const result = await campsCollection.deleteOne({
            _id: new ObjectId(campId),
          });

          if (result.deletedCount > 0) {
            // Also delete related registrations
            await registrationsCollection.deleteMany({
              campId: new ObjectId(campId),
            });

            res.json({
              success: true,
              deletedCount: result.deletedCount,
            });
          } else {
            res.status(404).json({
              success: false,
              message: "Camp not found",
            });
          }
        } catch (error) {
          console.error("Error deleting camp:", error);
          res.status(500).json({
            success: false,
            error: "Failed to delete camp",
            details: error.message,
          });
        }
      }
    );

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
    });

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
    });

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
    });

    // ============================
    // STATIC PUBLIC ROUTES END <<
    // ============================

    // Start Express server after DB connection is ready
    const PORT = process.env.PORT || 5000;
    app.get("/", (req, res) => {
      res.send("Medical Camp Management System Backend is Running");
    });

    // 404 Handler
    app.use((req, res) => {
      res.status(404).json({
        success: false,
        error: "Route not found"
      });
    });

    // Error Handler
    app.use((err, req, res, next) => {
      console.error(err.stack);
      res.status(500).json({
        success: false,
        error: "Internal server error",
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
      });
    });

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("MongoDB connection error:", error);
  }
}
run().catch(console.error);
