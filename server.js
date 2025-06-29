const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || "ajitquiz-secret";

// MongoDB connect
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// Models
const Admin = mongoose.model('Admin', new mongoose.Schema({ username: String, password: String }));
const Question = mongoose.model('Question', new mongoose.Schema({
  subject: String,
  chapter: String,
  question: String,
  options: [String],
  correct: String,
  explanation: String
}));

// Create supreme admin if not exists
(async () => {
  const exists = await Admin.findOne({ username: 'ajitquiz@53' });
  if (!exists) {
    const hash = await bcrypt.hash('ajit@15091997', 10);
    await Admin.create({ username: 'ajitquiz@53', password: hash });
    console.log('👑 Supreme admin created');
  }
})();

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid token" });
  }
}

// Routes
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { id: admin._id, username: admin.username, isAdmin: true },
    JWT_SECRET,
    { expiresIn: '2h' }
  );

  res.json({ token });
});

app.post('/api/admins', verifyToken, async (req, res) => {
  if (!req.user?.isAdmin) return res.status(403).json({ error: "Access denied" });

  const { username, password } = req.body;
  const exists = await Admin.findOne({ username });
  if (exists) return res.status(400).json({ error: 'Username already exists' });

  const hash = await bcrypt.hash(password, 10);
  await Admin.create({ username, password: hash });
  res.status(201).json({ success: true, message: 'Admin created' });
});

app.get('/api/subjects', async (req, res) => {
  const subjects = await Question.distinct('subject');
  res.json(subjects);
});

app.get('/api/subjects/:subject/chapters', async (req, res) => {
  const chapters = await Question.find({ subject: req.params.subject }).distinct('chapter');
  res.json(chapters);
});

app.get('/api/subjects/:subject/chapters/:chapter/questions', async (req, res) => {
  const questions = await Question.find(
    { subject: req.params.subject, chapter: req.params.chapter },
    '-__v -_id -subject -chapter'
  );
  res.json(questions);
});

app.post('/api/questions', verifyToken, async (req, res) => {
  if (!req.user?.isAdmin) return res.status(403).json({ error: "Access denied" });

  try {
    const q = new Question(req.body);
    await q.save();
    res.status(201).json({ message: 'Question added successfully' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
