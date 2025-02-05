import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import pkg from 'pg';

import dotenv from 'dotenv';
dotenv.config();


const { Client } = pkg;

const app = express();

// Check for environment variables, these will be injected in Vercel
if (!process.env.SECRET_KEY) {
    throw new Error("FATAL ERROR: SECRET_KEY is missing");
}

const PORT = process.env.PORT || 3001;
const SECRET_KEY = process.env.SECRET_KEY; 

// Database connection using Vercel's environment variables
const db = new Client({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'postgres', // Change to your PostgreSQL username
    password: process.env.DB_PASSWORD || '', // Change to your PostgreSQL password
    database: process.env.DB_NAME || 'user_auth', // Change to your PostgreSQL database name
    port: 5432 // Default PostgreSQL port
});

// Middleware
app.use(cors({
    origin: 'https://elegant-palmier-4bde1a.netlify.app/', // Update with your frontend URL
    methods: ['GET', 'POST', 'PUT'],
    credentials: true
}));
app.use(express.json());

const connectDB = () => {
    db.connect(err => {
        if (err) {
            console.error('Error connecting to PostgreSQL:', err);
            setTimeout(connectDB, 5000); // Retry after 5 seconds
        } else {
            console.log('✅ Connected to PostgreSQL');
        }
    });
};

connectDB();

// Token Generation
const generateToken = (user) => {
    return jwt.sign(
        {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role.trim().toLowerCase(),
            balances: {
                BTC: user.BTC || 0,
                ETH: user.ETH || 0,
                ADA: user.ADA || 0,
                XRP: user.XRP || 0,
                DOGE: user.DOGE || 0,
                BNB: user.BNB || 0,
                SOL: user.SOL || 0,
                DOT: user.DOT || 0,
                total: user.total || 0,
            },
        },
        SECRET_KEY,
        { expiresIn: '1h' }
    );
};

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized: No token provided' });

    const token = authHeader.split(' ')[1];

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            console.log("🚨 JWT Verification Failed:", err.message);
            return res.status(403).json({ error: 'Forbidden: Invalid token' });
        }

        console.log("✅ Decoded JWT Payload:", user);
        req.user = user;
        next();
    });
};

// Role Verification Middleware
const checkRole = (requiredRole) => {
    return (req, res, next) => {
        console.log(`Checking Role - Required: '${requiredRole}', User Role: '${req.user?.role}'`);
        if (!req.user || !req.user.role) return res.status(403).json({ error: 'Forbidden: No role found' });

        if (req.user.role.trim().toLowerCase() !== requiredRole.trim().toLowerCase()) {
            console.log(`🚨 Role mismatch - Blocking access! (User Role: '${req.user.role}')`);
            return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
        }

        console.log("✅ Role check passed - Access granted!");
        next();
    };
};

app.post('/auth/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ 
            error: 'All fields are required',
            missing: ['name', 'email', 'password'].filter(f => !req.body[f])
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)';

        db.query(query, [name, email, hashedPassword, "user"], (err, results) => {
            if (err) {
                if (err.code === '23505') { // PostgreSQL error for unique constraint violation (duplicate email)
                    return res.status(409).json({
                        error: 'Email already registered',
                        code: 'EMAIL_EXISTS'
                    });
                }
                console.error("❌ Database error:", err);
                return res.status(500).json({ 
                    error: 'Registration failed',
                    code: 'DB_ERROR'
                });
            }

            res.status(201).json({
                message: 'Registration successful',
                userId: results.rows[0].id, // PostgreSQL result format
                nextStep: '/auth/login'
            });
        });
    } catch (err) {
        console.error("❌ Registration error:", err);
        res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
});


// ✅ Debugging Log to Check All Registered Routes
app._router.stack.forEach((route) => {
    if (route.route && route.route.path) {
        console.log(`🛠 Registered Route: ${route.route.path}`);
    }
});

// ✅ Report Case Submission (Public)
app.post('/api/reports', (req, res) => {
    const { name, surname, email, description } = req.body;

    if (!name || !surname || !email || !description) {
        return res.status(400).json({ error: "All fields are required" });
    }

    const query = `
        INSERT INTO reports (name, surname, email, description, created_at)
        VALUES (?, ?, ?, ?, NOW())
    `;

    db.query(query, [name, surname, email, description], (err, result) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.status(201).json({ message: "Report submitted successfully!", reportId: result.insertId });
    });
});

// ✅ Contact Enquiry Submission (Public)
app.post('/api/contact', (req, res) => {
    const { enquiryType, fullName, email, phone, country, scamWebsite, lostMoney, message } = req.body;

    if (!enquiryType || !fullName || !email || !phone || !country || !message) {
        return res.status(400).json({ error: "All required fields must be filled" });
    }

    const query = `
        INSERT INTO enquiries (enquiryType, fullName, email, phone, country, scamWebsite, lostMoney, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `;

    db.query(query, [enquiryType, fullName, email, phone, country, scamWebsite || "", lostMoney || "", message], (err, result) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.status(201).json({ message: "Enquiry submitted successfully!", enquiryId: result.insertId });
    });
});


// ✅ Login Route (Now includes balances in JWT)
app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).send({ error: 'All fields are required' });

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) return res.status(500).send({ error: 'Database error' });
        if (results.length === 0) return res.status(404).send({ error: 'Invalid email or password' });

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).send({ error: 'Invalid email or password' });

        const token = generateToken(user);
        res.send({ message: 'Login successful', user, token });
    });
});

// ✅ Get All Users (Admin Only)
app.get('/api/users', authenticateJWT, checkRole('admin'), (req, res) => {
    console.log("✅ Admin access granted to /api/users");

    const query = 'SELECT id, name, email, role, BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total FROM users';
    db.query(query, (err, results) => {
        if (err) return res.status(500).send({ error: 'Database error' });
        res.send(results);
    });
});

// ✅ Get Reports (Admin Only)
app.get('/api/reports', authenticateJWT, checkRole('admin'), (req, res) => {
    console.log("✅ Admin access granted to /api/reports");

    const query = 'SELECT * FROM reports';
    db.query(query, (err, results) => {
        if (err) return res.status(500).send({ error: 'Database error' });
        res.send(results);
    });
});

// ✅ Update User Balances (Admin only)
app.put('/api/users/:id', authenticateJWT, checkRole('admin'), (req, res) => {
    const userId = req.params.id;
    const { BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total } = req.body;

    const query = `
        UPDATE users
        SET BTC = ?, ETH = ?, ADA = ?, XRP = ?, DOGE = ?, BNB = ?, SOL = ?, DOT = ?, total = ?
        WHERE id = ?
    `;

    db.query(query, [BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total, userId], (err, results) => {
        if (err) return res.status(500).send({ error: 'Database error' });
        if (results.affectedRows === 0) return res.status(404).send({ error: 'User not found' });

        res.send({ message: 'User updated successfully' });
    });
});

app.post('/api/investments', (req, res) => {
    const { first_name, last_name, phone_country_code, phone_number, email, investment_amount, details } = req.body;

    if (!first_name || !last_name || !phone_country_code || !phone_number || !email || !investment_amount) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    const query = `
        INSERT INTO investments (first_name, last_name, phone_country_code, phone_number, email, investment_amount, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(query, [first_name, last_name, phone_country_code, phone_number, email, investment_amount, details || ""], (err, result) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ error: "Database error" }); // ✅ Ensure JSON response
        }
        res.status(201).json({ message: "Investment submitted successfully!", investmentId: result.insertId });
    });
});



// ✅ Get All Investments (Admin Only)
app.get('/api/investments', authenticateJWT, checkRole('admin'), (req, res) => {
    console.log("✅ Admin access granted to /api/investments");

    const query = 'SELECT * FROM investments';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send({ error: 'Database error' });
        }
        res.send(results);
    });
});

// ✅ Get All Contact Enquiries (Admin Only)
app.get('/api/contact', authenticateJWT, checkRole('admin'), (req, res) => {
    console.log("✅ Admin access granted to /api/contact");

    const query = 'SELECT * FROM enquiries';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send({ error: 'Database error' });
        }
        res.send(results);
    });
});

app.put('/api/trade', authenticateJWT, (req, res) => {
    const { userId, fromCurrency, toCurrency, amount, conversionRate } = req.body;

    if (!userId || !fromCurrency || !toCurrency || !amount || !conversionRate) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Convert amount based on the exchange rate
    const convertedAmount = amount * conversionRate;

    // Ensure user has enough balance to trade
    const checkBalanceQuery = `SELECT ${fromCurrency} FROM users WHERE id = ?`;
    db.query(checkBalanceQuery, [userId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const currentBalance = results[0][fromCurrency];
        if (currentBalance < amount) {
            return res.status(400).json({ error: `Insufficient ${fromCurrency} balance` });
        }

        // Update balances
        const tradeQuery = `
            UPDATE users
            SET ${fromCurrency} = ${fromCurrency} - ?, ${toCurrency} = ${toCurrency} + ?
            WHERE id = ?
        `;

        db.query(tradeQuery, [amount, convertedAmount, userId], (err, result) => {
            if (err) {
                console.error('Error updating balances:', err);
                return res.status(500).send({ error: 'Trade execution failed' });
            }
            res.json({ message: 'Trade successful', convertedAmount });
        });
    });
});

// ✅ Get User Balances by ID (Fix 404 Error)
app.get('/api/users/:id', authenticateJWT, (req, res) => {
    const userId = req.params.id;

    console.log("🔍 Fetching user balances for ID:", userId); // ✅ Debugging Log

    const query = `SELECT BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total FROM users WHERE id = ?`;
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('❌ Database error:', err);
            return res.status(500).send({ error: 'Database error' });
        }

        if (results.length === 0) {
            console.warn("⚠️ No user found for ID:", userId); // ✅ Debugging Log
            return res.status(404).json({ error: 'User not found' });
        }

        console.log("✅ User Balances:", results[0]); // ✅ Debugging Log
        res.json(results[0]); // Return user balances
    });
});

// ✅ Update User's Total Balance in `users` Table
app.put('/api/update-total/:id', authenticateJWT, (req, res) => {
    const userId = req.params.id;
    const { total } = req.body;

    if (!total || isNaN(total)) {
        return res.status(400).send({ error: "Invalid total value" });
    }

    const query = `UPDATE users SET total = ? WHERE id = ?`;

    db.query(query, [total, userId], (err, results) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).send({ error: "Database error" });
        }
        if (results.affectedRows === 0) {
            return res.status(404).send({ error: "User not found" });
        }

        console.log(`✅ Updated total balance for user ${userId}: $${total}`);
        res.send({ message: "Total balance updated successfully", total });
    });
});

app.listen(5000, console.log("Server listening in port 5000"));