const express = require('express');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware Security
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 30 * 60 * 1000 } // 30 minutes
}));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: 'Too many attempts. Try again later.'
});
app.use('/api/', limiter);

// Encryption
const ENCRYPTION_KEY = crypto.scryptSync(
    process.env.ENCRYPTION_KEY || 'github-access-2025-secret-key-32char', 
    'salt', 
    32
);
const IV_LENGTH = 16;

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = parts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Mission Configuration
const missions = {
    2: {
        id: 2,
        title: "GitHub Access Mission",
        hexChallenge: "47 69 74 48 75 62 20 65 6e 63 6f 64 69 6e 67 20 63 68 61 6c 6c 65 6e 67 65 3a 20 54 68 65 20 63 6f 64 65 20 69 73 20 22 47 48 5f 41 43 43 45 53 53 5f 32 30 32 35 5f 58 37 59 33 22",
        correctAnswers: [
            "github encoding challenge: the code is \"gh_access_2025_x7y3\"",
            "gh_access_2025_x7y3",
            "GH_ACCESS_2025_X7Y3"
        ],
        githubLink: "https://github.com/owner-private/repo-access",
        accessCode: "GH_ACCESS_2025_X7Y3",
        timeLimit: 300, // 5 minutes
        maxAttempts: 5
    }
};

// Store active sessions
const activeSessions = new Map();

// API Routes

// 1. Initialize Mission
app.post('/api/init-mission', (req, res) => {
    const sessionId = crypto.randomBytes(16).toString('hex');
    const userIp = req.ip || req.connection.remoteAddress;
    
    activeSessions.set(sessionId, {
        ip: userIp,
        startTime: Date.now(),
        attempts: 0,
        completed: false,
        githubLinkAccessed: false
    });
    
    // Encrypt session data
    const encryptedSession = encrypt(JSON.stringify({
        sessionId,
        startTime: Date.now(),
        missionId: 2
    }));
    
    res.json({
        success: true,
        sessionToken: encryptedSession,
        mission: {
            hexChallenge: missions[2].hexChallenge,
            timeLimit: missions[2].timeLimit,
            maxAttempts: missions[2].maxAttempts
        },
        message: "Mission timer started! You have 5 minutes."
    });
});

// 2. Verify Answer
app.post('/api/verify-answer', (req, res) => {
    const { sessionToken, answer } = req.body;
    
    if (!sessionToken || !answer) {
        return res.status(400).json({ 
            success: false, 
            message: "Missing session token or answer" 
        });
    }
    
    // Decrypt and verify session
    let sessionData;
    try {
        sessionData = JSON.parse(decrypt(sessionToken));
    } catch (error) {
        return res.status(401).json({ 
            success: false, 
            message: "Invalid session token" 
        });
    }
    
    const userSession = activeSessions.get(sessionData.sessionId);
    if (!userSession) {
        return res.status(401).json({ 
            success: false, 
            message: "Session expired" 
        });
    }
    
    // Check time limit
    const timeElapsed = Math.floor((Date.now() - userSession.startTime) / 1000);
    if (timeElapsed > missions[2].timeLimit) {
        activeSessions.delete(sessionData.sessionId);
        return res.status(400).json({ 
            success: false, 
            message: "Time's up! Mission expired." 
        });
    }
    
    // Check attempt limit
    if (userSession.attempts >= missions[2].maxAttempts) {
        return res.status(429).json({ 
            success: false, 
            message: "Too many attempts. Mission failed." 
        });
    }
    
    // Increment attempts
    userSession.attempts++;
    
    // Check answer
    const userAnswer = answer.trim().toLowerCase();
    const isCorrect = missions[2].correctAnswers.some(correct => 
        correct.toLowerCase() === userAnswer
    );
    
    if (isCorrect) {
        // Mission completed successfully
        userSession.completed = true;
        userSession.completionTime = Date.now();
        
        // Generate encrypted GitHub link with expiration
        const linkData = {
            githubLink: missions[2].githubLink,
            accessCode: missions[2].accessCode,
            expiresAt: Date.now() + (24 * 60 * 60 * 1000), // 24 hours
            sessionId: sessionData.sessionId
        };
        
        const encryptedLink = encrypt(JSON.stringify(linkData));
        
        return res.json({
            success: true,
            correct: true,
            message: "🎉 CORRECT! GitHub access granted!",
            encryptedLink: encryptedLink,
            autoCopy: true, // Flag untuk frontend melakukan auto-copy
            copyText: missions[2].githubLink,
            accessCode: missions[2].accessCode,
            attempts: userSession.attempts,
            timeTaken: timeElapsed
        });
    } else {
        // Wrong answer
        return res.json({
            success: false,
            correct: false,
            message: `❌ Wrong answer! Attempts: ${userSession.attempts}/${missions[2].maxAttempts}`,
            attempts: userSession.attempts,
            attemptsLeft: missions[2].maxAttempts - userSession.attempts,
            autoCopy: false // Tidak ada auto-copy untuk jawaban salah
        });
    }
});

// 3. Get GitHub Link (after verification)
app.post('/api/get-github-link', (req, res) => {
    const { sessionToken } = req.body;
    
    if (!sessionToken) {
        return res.status(400).json({ 
            success: false, 
            message: "Session token required" 
        });
    }
    
    let sessionData;
    try {
        sessionData = JSON.parse(decrypt(sessionToken));
    } catch (error) {
        return res.status(401).json({ 
            success: false, 
            message: "Invalid session token" 
        });
    }
    
    const userSession = activeSessions.get(sessionData.sessionId);
    if (!userSession || !userSession.completed) {
        return res.status(403).json({ 
            success: false, 
            message: "Mission not completed or session expired" 
        });
    }
    
    // Check if link was already accessed
    if (userSession.githubLinkAccessed) {
        return res.status(403).json({ 
            success: false, 
            message: "GitHub link already accessed" 
        });
    }
    
    userSession.githubLinkAccessed = true;
    
    // Return the GitHub link
    res.json({
        success: true,
        githubLink: missions[2].githubLink,
        accessCode: missions[2].accessCode,
        message: "Use this link to access the GitHub repository"
    });
});

// 4. Check Session Status
app.post('/api/session-status', (req, res) => {
    const { sessionToken } = req.body;
    
    if (!sessionToken) {
        return res.status(400).json({ 
            success: false, 
            message: "Session token required" 
        });
    }
    
    let sessionData;
    try {
        sessionData = JSON.parse(decrypt(sessionToken));
    } catch (error) {
        return res.status(401).json({ 
            success: false, 
            message: "Invalid session token" 
        });
    }
    
    const userSession = activeSessions.get(sessionData.sessionId);
    if (!userSession) {
        return res.json({ 
            success: false, 
            expired: true,
            message: "Session expired" 
        });
    }
    
    const timeElapsed = Math.floor((Date.now() - userSession.startTime) / 1000);
    const timeLeft = Math.max(0, missions[2].timeLimit - timeElapsed);
    
    res.json({
        success: true,
        session: {
            attempts: userSession.attempts,
            completed: userSession.completed,
            timeElapsed,
            timeLeft,
            timeLimit: missions[2].timeLimit,
            maxAttempts: missions[2].maxAttempts
        }
    });
});

// 5. Cleanup expired sessions (cron job bisa ditambahkan)
app.get('/api/cleanup', (req, res) => {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [sessionId, session] of activeSessions.entries()) {
        if (now - session.startTime > (missions[2].timeLimit * 1000) + 60000) { // + 1 minute buffer
            activeSessions.delete(sessionId);
            cleaned++;
        }
    }
    
    res.json({ 
        success: true, 
        message: `Cleaned ${cleaned} expired sessions` 
    });
});

// Serve main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`⏰ Mission time limit: ${missions[2].timeLimit} seconds`);
    console.log(`🔐 Encryption enabled`);
});
