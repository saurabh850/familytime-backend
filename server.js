require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// --- CONFIG ---
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

if (!MONGODB_URI || !JWT_SECRET) {
    console.error("❌ Mising .env variables");
    process.exit(1);
}

// --- CORS (Production) ---
app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || "*",
    methods: ['GET', 'POST', 'DELETE', 'PUT', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// --- MONGODB CONNECTION ---
mongoose.connect(MONGODB_URI, {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    family: 4 // Force IPv4 to avoid some SSL/DNS issues
})
    .then(() => console.log(`✅ MongoDB Connected`))
    .catch(err => console.error("❌ MongoDB Connection Error:", err));

// --- SCHEMAS ---

// 1. USER SCHEMA
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password_hash: { type: String, required: true },
    family_code: { type: String, required: true, unique: true },
    viewers: [{ name: String, joinedAt: { type: Date, default: Date.now } }]
});
const User = mongoose.model('User', UserSchema);

// 2. CLASS SESSION SCHEMA
const ClassSchema = new mongoose.Schema({
    owner_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    subject: String,
    weekday: Number, // 1 = Mon, 7 = Sun
    start_hour: Number,
    start_minute: Number,
    end_hour: Number,
    end_minute: Number,
    is_break: Boolean
});
const ClassSession = mongoose.model('Class', ClassSchema);

// --- HELPERS ---
function generateCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let result = '';
    for (let i = 0; i < 5; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// --- MIDDLEWARE ---
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Access denied" });

    const token = authHeader.split(' ')[1];
    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.userId = verified.id;
        next();
    } catch (err) {
        res.status(401).json({ error: "Invalid Token" });
    }
};

// --- ROUTES ---

// 0. HEALTH CHECK
app.get('/', (req, res) => {
    res.send("✅ Server is Running!");
});

// 1. REGISTER (Student)
app.post('/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check duplicate
        const existing = await User.findOne({ username });
        if (existing) return res.status(400).json({ error: "Username already exists" });

        // Hash Password
        const hash = await bcrypt.hash(password, 10);

        // Generate Code
        const code = generateCode();

        // Save
        const newUser = new User({ username, password_hash: hash, family_code: code });
        await newUser.save();

        res.json({ message: "User created", family_code: code });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 2. LOGIN (Student)
app.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: "Invalid credentials" });

        // Check Password
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(400).json({ error: "Invalid credentials" });

        // Generate Token
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });

        res.json({ token, family_code: user.family_code });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 2.1 JOIN FAMILY (Parent)
app.post('/auth/join', async (req, res) => {
    try {
        const { code, name } = req.body;
        const user = await User.findOne({ family_code: code });
        if (!user) return res.status(404).json({ error: "Invalid Access Code" });

        // Add to viewers list if new
        if (name) {
            const exists = user.viewers && user.viewers.find(v => v.name === name);
            if (!exists) {
                user.viewers.push({ name });
                await user.save();
            }
        }
        res.json({ message: "Joined", family_code: code });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 2.2 LEAVE FAMILY (Parent Logout)
app.post('/auth/leave', async (req, res) => {
    try {
        const { code, name } = req.body;
        const user = await User.findOne({ family_code: code });
        if (!user) return res.status(404).json({ error: "Invalid Access Code" });

        // Remove from viewers list
        if (name && user.viewers) {
            user.viewers = user.viewers.filter(v => v.name !== name);
            await user.save();
        }
        res.json({ message: "Left family" });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 2.2 GET VIEWERS (For Settings)
app.get('/viewers', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(user.viewers || []);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 3. EXAM SCHEMA
const ExamSchema = new mongoose.Schema({
    owner_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    subject: String,
    date: Date,
    time_hour: Number,
    time_minute: Number,
    syllabus: String
});
const Exam = mongoose.model('Exam', ExamSchema);

// 4. NOTE SCHEMA
const NoteSchema = new mongoose.Schema({
    owner_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: String
});
const Note = mongoose.model('Note', NoteSchema);

// --- PUBLIC ROUTES (For Parents) ---

app.get('/public/classes', async (req, res) => {
    try {
        const { code } = req.query;
        const user = await User.findOne({ family_code: code });
        if (!user) return res.status(404).json({ error: "Invalid Access Code" });

        const classes = await ClassSession.find({ owner_id: user._id });
        res.json(classes);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/public/exams', async (req, res) => {
    try {
        const { code } = req.query;
        const user = await User.findOne({ family_code: code });
        if (!user) return res.status(404).json({ error: "Invalid Access Code" });

        const exams = await Exam.find({ owner_id: user._id });
        res.json(exams);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/public/notes', async (req, res) => {
    try {
        const { code } = req.query;
        const user = await User.findOne({ family_code: code });
        if (!user) return res.status(404).json({ error: "Invalid Access Code" });

        const notes = await Note.find({ owner_id: user._id });
        res.json(notes);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- PRIVATE ROUTES (Authenticated Students) ---

app.get('/classes', authenticate, async (req, res) => {
    const classes = await ClassSession.find({ owner_id: req.userId });
    res.json(classes);
});
app.post('/classes', authenticate, async (req, res) => {
    const newClass = new ClassSession({ ...req.body, owner_id: req.userId });
    await newClass.save();
    res.json(newClass);
});

app.get('/exams', authenticate, async (req, res) => {
    const exams = await Exam.find({ owner_id: req.userId });
    res.json(exams);
});
app.post('/exams', authenticate, async (req, res) => {
    const newExam = new Exam({ ...req.body, owner_id: req.userId });
    await newExam.save();
    res.json(newExam);
});

app.get('/notes', authenticate, async (req, res) => {
    const notes = await Note.find({ owner_id: req.userId });
    res.json(notes);
});
app.post('/notes', authenticate, async (req, res) => {
    const newNote = new Note({ ...req.body, owner_id: req.userId });
    await newNote.save();
    res.json(newNote);
});

// 8. DELETE ROUTES
app.delete('/classes/:id', authenticate, async (req, res) => {
    try {
        await ClassSession.deleteOne({ _id: req.params.id, owner_id: req.userId });
        res.json({ message: "Deleted" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/exams/:id', authenticate, async (req, res) => {
    try {
        await Exam.deleteOne({ _id: req.params.id, owner_id: req.userId });
        res.json({ message: "Deleted" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/notes/:id', authenticate, async (req, res) => {
    try {
        await Note.deleteOne({ _id: req.params.id, owner_id: req.userId });
        res.json({ message: "Deleted" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});




// START
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
