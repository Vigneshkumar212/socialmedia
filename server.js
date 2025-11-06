
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const fs = require('fs').promises;
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const JWT_SECRET = 'your-super-secret-and-long-key-that-should-be-random';

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// --- Middleware ---
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // Serve uploaded files

const dbPath = path.join(__dirname, 'db');
const usersPath = path.join(dbPath, 'users.json');
const postsPath = path.join(dbPath, 'posts.json');
const followsPath = path.join(dbPath, 'follows.json');

// Ensure db and uploads directories exist
fs.mkdir(dbPath, { recursive: true }).catch(console.error);
fs.mkdir(path.join(__dirname, 'uploads'), { recursive: true }).catch(console.error);

// --- Multer Configuration ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
        cb(null, true);
    } else {
        cb(new Error('Not an image or video!'), false);
    }
};

const upload = multer({ storage, fileFilter });

// --- JSON Database Helpers (no changes) ---
async function readDB(filePath, defaultData = {}) {
    try {
        const data = await fs.readFile(filePath, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            await writeDB(filePath, defaultData);
            return defaultData;
        }
        throw error;
    }
}

async function writeDB(filePath, data) {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

// --- Express HTTP Routes ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password are required' });
    const db = await readDB(usersPath, { users: {} });
    if (db.users[username]) return res.status(409).json({ message: 'Username already exists' });
    const passwordHash = await bcrypt.hash(password, 10);
    db.users[username] = { username, passwordHash };
    const followsDb = await readDB(followsPath, { following: {} });
    if (!followsDb.following[username]) followsDb.following[username] = [];
    await writeDB(usersPath, db);
    await writeDB(followsPath, followsDb);
    res.status(201).json({ message: 'Account created successfully. Please log in.' });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required' });
    const db = await readDB(usersPath, { users: {} });
    const user = db.users[username];
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (isMatch) {
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '5h' });
        res.cookie('token', token, { httpOnly: true, secure: false, maxAge: 5 * 3600000, sameSite: 'strict' });
        res.status(200).json({ username });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token').status(200).json({ message: 'Logged out' });
});

app.get('/api/session-check', (req, res) => {
    try {
        const decoded = jwt.verify(req.cookies.token, JWT_SECRET);
        res.status(200).json({ username: decoded.username });
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

// --- NEW: API Endpoint for Creating Posts with Media ---
app.post('/api/posts', upload.single('media'), async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: 'Not authenticated' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const username = decoded.username;
        const { text } = req.body;
        const mediaPath = req.file ? `/uploads/${req.file.filename}` : null;

        if (!text && !mediaPath) {
            return res.status(400).json({ message: 'Post must include text or a file.' });
        }

        const postsDb = await readDB(postsPath, { posts: [] });
        const newPost = {
            postId: Date.now().toString(),
            text,
            mediaPath, // Add media path to post object
            mediaType: req.file ? req.file.mimetype : null,
            authorUsername: username,
            timestamp: new Date().toISOString(),
        };

        postsDb.posts.unshift(newPost);
        await writeDB(postsPath, postsDb);

        // Broadcast the new post to all connected clients
        io.emit('newPost', newPost);
        res.status(201).json(newPost);

    } catch (err) {
        console.error(err);
        res.status(401).json({ message: 'Invalid token' });
    }
});


// --- Socket.IO Middleware and Events (mostly unchanged) ---
io.use((socket, next) => {
    const cookieString = socket.handshake.headers.cookie || '';
    const token = cookieString.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
    if (!token) return next(new Error('Authentication error'));
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.username = decoded.username;
        next();
    } catch (err) {
        next(new Error('Authentication error'));
    }
});

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.username}`);

  socket.on('getFeed', async () => {
    const followsDb = await readDB(followsPath, { following: {} });
    const postsDb = await readDB(postsPath, { posts: [] });
    const followingList = [...(followsDb.following[socket.username] || []), socket.username];
    const feedPosts = postsDb.posts.filter(post => followingList.includes(post.authorUsername));
    socket.emit('feedData', feedPosts);
  });

  socket.on('getAllUsers', async () => {
    const usersDb = await readDB(usersPath, { users: {} });
    const followsDb = await readDB(followsPath, { following: {} });
    const allUsers = Object.keys(usersDb.users);
    const followingList = followsDb.following[socket.username] || [];
    socket.emit('allUsers', { allUsers, following: followingList });
  });

  socket.on('followUser', async ({ usernameToFollow }) => {
    if (socket.username === usernameToFollow) return;
    const followsDb = await readDB(followsPath, { following: {} });
    const followingList = followsDb.following[socket.username] || [];
    if (!followingList.includes(usernameToFollow)) {
      followsDb.following[socket.username].push(usernameToFollow);
      await writeDB(followsPath, followsDb);
      socket.emit('follow_success', { username: usernameToFollow });
    }
  });

  socket.on('disconnect', () => console.log(`User disconnected: ${socket.username}`))
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

