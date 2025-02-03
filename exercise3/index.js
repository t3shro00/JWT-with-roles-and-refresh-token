require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy;

const app = express();
const port = 3003;

// Secret key for JWT. It should be in the .env file
const JWT_SECRET = process.env.JWT_SECRET || '123456';

const users = {
  admin: { username: 'admin', password: 'admin', role: 'admin' },
  user: { username: 'user', password: 'password', role: 'user' }
};

// Basic Strategy for Passport
passport.use(new BasicStrategy(
  function (username, password, done) {
    const user = users[username];
    if (user && user.password === password) {
      // Generate JWT
      const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
      return done(null, { username: user.username, role: user.role, token });
    } else {
      return done(null, false);
    }
  }
));

const authenticate = passport.authenticate('basic', { session: false });

app.use(express.json());

// Middleware to verify the token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Middleware to check if the user has the required role
const checkRole = (role) => (req, res, next) => {
  if (req.user.role === role) {
    next();
  } else {
    res.status(403).json({ message: 'Forbidden' });
  }
};

// In-memory posts array
const posts = [
  "The early bird catches the worm",
  "A journey of a thousand miles begins with a single step",
  "No pain, no gain"
];

// Home Route
app.get('/', (req, res) => {
  res.send('Hello World!');
});

// Signin Route
app.get('/signin', authenticate, (req, res) => {
  const { username, role } = req.user;
  // Create a token with the username and send it as a response
  const token = jwt.sign({ username, role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Protected Posts Route (GET)
app.get('/posts', verifyToken, (req, res) => {
  res.json(posts);
});

// Add a new Post (POST) - Only accessible to admin
app.post('/posts', verifyToken, checkRole('admin'), (req, res) => {
  const newPost = req.body.post;
  if (!newPost) {
    return res.status(400).json({ message: 'No post provided' });
  }
  posts.push(newPost);
  res.json({ message: 'Post added successfully', post: newPost });
});

// Start the server
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
