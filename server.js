const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config(); // 🟢 Load .env variables

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ✅ Connect to MongoDB using secure URI
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Schemas
const Admin = mongoose.model('Admin', new mongoose.Schema({ username: String, password: String }));
const Question = mongoose.model('Question', new mongoose.Schema({
  subject: String, chapter: String, question: String,
  options: [String], correct: String, explanation: String
}));

// 🛡️ Supreme admin creation (if not exists)
(async () => {
  const exists = await Admin.findOne({ username: 'ajitquiz@53' });
  if (!exists) {
    const hash = await bcrypt.hash('ajit@15091997', 10);
    await Admin.create({ username: 'ajitquiz@53', password: hash });
    console.log('👑 Supreme admin created');
  }
})();

// APIs
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ success: true });
});

app.post('/api/admins', async (req, res) => {
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
  const questions = await Question.find({ subject: req.params.subject, chapter: req.params.chapter },
    '-__v -_id -subject -chapter');
  res.json(questions);
});

app.post('/api/questions', async (req, res) => {
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
