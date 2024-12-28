require("dotenv").config();
const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection URL
const uri = process.env.DATABASE_URL;

const client = new MongoClient(uri, {
  serverApi: ServerApiVersion.v1,
});

// Middleware for authenticating tokens
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Bearer <token>

  if (!token) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user; // Store user data in request
    next();
  });
};

// Connect to MongoDB and set up routes
const run = async () => {
  try {
    await client.connect(); // Connect to MongoDB
    const db = client.db("KfcKafe");
    const usersCollection = db.collection("users"); // For users registration and login

    /* --------- User Authentication --------- */

    // Registration route
    app.post("/auth/register", async (req, res) => {
      const { name, email, password } = req.body; // username

      if (!email || !password || !name) {
        return res
          .status(400)
          .json({ message: "Username and password are required." });
      }

      const existingUser = await usersCollection.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "User already exists." });
      }

      // Hash the password before saving
      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = { name, email, password: hashedPassword }; // Store hashed password
      await usersCollection.insertOne(newUser);

      res.status(201).json({ message: "User registered successfully" });
    });

    // Login route
    app.post("/auth/login", async (req, res) => {
      const { email, password } = req.body;

      if (!email || !password) {
        return res
          .status(400)
          .json({ message: "Username and password are required." });
      }

      const user = await usersCollection.findOne({ email });

      if (!user) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Verify password
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Generate JWT token
      const token = jwt.sign(
        { id: user._id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "1h" } // Token expiration time
      );

      res.status(200).json({ message: "User logged in successfully", token });
    });

    /* --------- Other Routes --------- */

    // Get user data
    app.get("/users", authenticateToken, async (req, res) => {
      try {
        const user = await usersCollection.findOne({ email: req.user.email });
        if (!user) return res.sendStatus(404); // Not Found
        const { password, ...userData } = user; // Exclude password
        res.status(200).json(userData);
      } catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
      }
    });

    //payment related api

    //-----------------------------------------

    // Task routes
  } finally {
    // You can close the client connection when necessary
  }
};

// Run the server
run().catch(console.dir);

// Home route
app.get("/", (req, res) => {
  res.send("Welcome to KFC Kafe Project!");
});

// Start the server
app.listen(port, () => {
  console.log(`KFC Kafe Project listening on port ${port}`);
});
