require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy;

const app = express();
const port = 3001;

// Secret key for JWT. It should be in the .env file
const JWT_SECRET = process.env.JWT_SECRET || '123456';

// Basic Strategy for Passport
passport.use(new BasicStrategy(
    function (username, password, done) {
        if (username === 'admin' && password === 'admin') {
            const user = { username: 'admin' };  // User details (can be from a database)
            const token = jwt.sign(user, 'JWT_SECRET', { expiresIn: '1h' });  // Generate JWT
            return done(null, user, { token });  // Send token back as part of user object
          } else {
            return done(null, false);
        }
    }
));

const authenticate = passport.authenticate('basic', { session: false });

app.use(express.json());

// Home Route
app.get('/', (req, res) => {
    res.send('Hello World!');
});

// Signin Route
app.get('/signin', authenticate, (req, res) => {
    const { username } = req.user;
    // Create a token with the username and send it as a response
    // Allow access to the user for 1 hour
    const token = jwt.sign({
        username
    }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

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

// Protected Posts Route
app.get('/posts', verifyToken, (req, res) => {
    const posts = [
        "The early bird catches the worm",
        "A journey of a thousand miles begins with a single step",
        "No pain, no gain"
    ];
    res.json(posts);
});

// Start the server
app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});
