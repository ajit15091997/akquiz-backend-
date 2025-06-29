const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Models
const Admin = mongoose.model('Admin', new mongoose.Schema({ username: String, password: String }));
const Question = mongoose.model('Question', new mongoose.Schema({
  subject: String, chapter: String, question: String,
  options: [String], correct: String, explanation: String
}));

// Create Supreme Admin if not exists
(async () => {
  const exists = await Admin.findOne({ username: 'ajitquiz@53' });
  if (!exists) {
    const hash = await bcrypt.hash('ajit@15091997', 10);
    await Admin.create({ username: 'ajitquiz@53', password: hash });
    console.log('👑 Supreme admin created');
  }
})();

// JWT middleware
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(403).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Is Supreme Admin middleware
const isSupreme = (req, res, next) => {
  if (req.admin.username !== 'ajitquiz@53') {
    return res.status(403).json({ error: 'Only Supreme Admin allowed' });
  }
  next();
};

// Routes
app.get('/', (req, res) => {
  res.send('🟢 AKQuiz Backend is Running Successfully!');
});

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ username: admin.username }, process.env.JWT_SECRET, { expiresIn: '3h' });
  res.json({ token });
});

app.post('/api/admins', verifyToken, isSupreme, async (req, res) => {
  const { username, password } = req.body;
  const exists = await Admin.findOne({ username });
  if (exists) return res.status(400).json({ error: 'Username already exists' });

  const hash = await bcrypt.hash(password, 10);
  await Admin.create({ username, password: hash });
  res.status(201).json({ message: 'Admin created' });
});

app.delete('/api/admins/:username', verifyToken, isSupreme, async (req, res) => {
  const { username } = req.params;
  if (username === 'ajitquiz@53') return res.status(400).json({ error: 'Cannot delete Supreme Admin' });

  const result = await Admin.deleteOne({ username });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Admin not found' });
  res.json({ message: 'Admin deleted' });
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
  const questions = await Question.find({ subject: req.params.subject, chapter: req.params.chapter },
    '-__v -_id -subject -chapter');
  res.json(questions);
});

app.post('/api/questions', verifyToken, async (req, res) => {
  try {
    const q = new Question(req.body);
    await q.save();
    res.status(201).json({ message: 'Question added successfully' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
