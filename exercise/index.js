require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy;
const cookieParser = require('cookie-parser');

const app = express();
const port = 3004;

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || '123456';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'refresh_secret';
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

// In-memory storage for refresh tokens (should be stored in a database in production)
const refreshTokens = new Map();

const users = {
    admin: { username: 'admin', password: 'admin', role: 'admin' },
    user: { username: 'user', password: 'password', role: 'user' }
};

passport.use(new BasicStrategy((username, password, done) => {
    const user = users[username];
    if (user && user.password === password) {
        return done(null, { username: user.username, role: user.role });
    } else {
        return done(null, false);
    }
}));

const authenticate = passport.authenticate('basic', { session: false });

app.use(express.json());
app.use(cookieParser());

const generateTokens = (user) => {
    const accessToken = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ username: user.username }, REFRESH_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });

    refreshTokens.set(refreshToken, user.username);
    return { accessToken, refreshToken };
};

const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Invalid token' });
        req.user = decoded;
        next();
    });
};

const checkRole = (role) => (req, res, next) => {
    if (req.user.role === role) {
        next();
    } else {
        res.status(403).json({ message: 'Forbidden' });
    }
};

// Login Route - Issues Access & Refresh Tokens
app.post('/login', authenticate, (req, res) => {
    const { username, role } = req.user;
    const { accessToken, refreshToken } = generateTokens({ username, role });

    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true, sameSite: 'Strict' });
    res.json({ accessToken });
});

// Refresh Token Route
app.post('/refresh', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken || !refreshTokens.has(refreshToken)) {
        return res.status(403).json({ message: 'Refresh token invalid or expired' });
    }

    jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Invalid refresh token' });

        const user = users[decoded.username];
        if (!user) return res.status(403).json({ message: 'User not found' });

        const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);
        refreshTokens.delete(refreshToken);
        refreshTokens.set(newRefreshToken, user.username);

        res.cookie('refreshToken', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'Strict' });
        res.json({ accessToken });
    });
});

// Logout Route
app.post('/logout', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) refreshTokens.delete(refreshToken);
    
    res.clearCookie('refreshToken');
    res.json({ message: 'Logged out successfully' });
});

// Protected Routes
app.get('/admin', verifyToken, checkRole('admin'), (req, res) => {
    res.json({ message: 'Admin access granted' });
});

app.get('/user', verifyToken, checkRole('user'), (req, res) => {
    res.json({ message: 'User access granted' });
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
