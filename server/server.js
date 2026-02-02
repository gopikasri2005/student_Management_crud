require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.use(express.json());
app.use(cors());

// --- MongoDB Connection ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error(err));

// --- Schemas ---
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
}));

const Student = mongoose.model('Student', new mongoose.Schema({
  name: String, email: String, dob: String, gender: String,
  studentId: String, dept: String, year: String,
  phone: String, address: String, gpa: Number
}));

// --- Routes ---

// Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashed });
    res.status(201).json({ message: "User Created" });
  } catch (err) {
    res.status(400).json({ error: "Email already exists" });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ token, name: user.name });
  } else {
    res.status(401).json({ error: "Invalid Credentials" });
  }
});

// Google Login
app.post('/api/google-login', async (req, res) => {
  try {
    const { token } = req.body;
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const { email, name } = ticket.getPayload();

    let user = await User.findOne({ email });
    if (!user) user = await User.create({ name, email, password: 'google-auth-user' });

    const jwtToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ token: jwtToken, name });
  } catch (err) {
    res.status(400).json({ error: "Google login failed" });
  }
});

// Students CRUD
app.get('/api/students', async (req, res) => {
  res.json(await Student.find());
});

app.post('/api/students', async (req, res) => {
  res.json(await Student.create(req.body));
});

app.put('/api/students/:id', async (req, res) => {
  try {
    const updated = await Student.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updated);
  } catch {
    res.status(400).json({ error: "Update failed" });
  }
});

app.delete('/api/students/:id', async (req, res) => {
  res.json(await Student.findByIdAndDelete(req.params.id));
});

// Start server
app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));
