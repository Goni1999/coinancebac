import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import pkg from 'pg';
import dotenv from 'dotenv';

dotenv.config();
const port = process.env.PORT || 5000;

const { Client } = pkg;

const app = express();

// Ensure SECRET_KEY exists in .env
if (!process.env.SECRET_KEY) {
    throw new Error("FATAL ERROR: SECRET_KEY is missing");
}

// Fetch environment variables
const SECRET_KEY = process.env.SECRET_KEY; 

// Database connection using Neon PostgreSQL URL from .env
const db = new Client({
    connectionString: process.env.DATABASE_URL, // Use DATABASE_URL from .env
    ssl: {
        rejectUnauthorized: false, // Necessary for SSL connections with Neon
    },
});

const corsOptions = {
    origin: 'https://coinance.co', // Replace with your frontend domain
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allow specific HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'], // Allow specific headers
  };

app.use(cors(corsOptions));

app.use(express.json());

// Connect to the PostgreSQL database
const connectDB = async () => {
    try {
        await db.connect(); // Connect to the Neon PostgreSQL DB
        console.log('✅ Connected to PostgreSQL');
    } catch (err) {
        console.error('Error connecting to PostgreSQL:', err);
        setTimeout(connectDB, 5000); // Retry after 5 seconds
    }
};

connectDB();

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token from 'Authorization' header

    if (!token) {
        return res.status(401).send({ error: 'Unauthorized: No token provided' }); // Token is missing
    }

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).send({ error: 'Unauthorized: Invalid or expired token' }); // Invalid token
        }

        req.user = user; // Attach user to request object
        next(); // Proceed to the next middleware or route handler
    });
};

const checkRole = (requiredRole) => {
    return (req, res, next) => {
        // Log for debugging role check
        console.log(`Checking Role - Required: '${requiredRole}', User Role: '${req.user?.role}'`);

        // Ensure that the user object exists and contains a role
        if (!req.user) {
            console.log("🚨 No user found in request");
            return res.status(403).json({ error: 'Forbidden: User not authenticated' });
        }

        // Check if role is present in user object
        if (!req.user.role) {
            console.log("🚨 No role found in user object");
            return res.status(403).json({ error: 'Forbidden: No role found' });
        }

        // Check if user's role matches required role
        const userRole = req.user.role.trim().toLowerCase();
        const requiredRoleTrimmed = requiredRole.trim().toLowerCase();

        if (userRole !== requiredRoleTrimmed) {
            console.log(`🚨 Role mismatch - Blocking access! (User Role: '${req.user.role}')`);
            return res.status(403).json({ error: `Forbidden: Insufficient permissions for '${requiredRole}'` });
        }

        console.log("✅ Role check passed - Access granted!");
        next(); // Continue to next middleware or route handler
    };
};

app.post('/api/investments', async (req, res) => {
    const { first_name, last_name, phone_country_code, phone_number, email, investment_amount, details } = req.body;

    if (!first_name || !last_name || !phone_country_code || !phone_number || !email || !investment_amount) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    const query = `
        INSERT INTO investments (first_name, last_name, phone_country_code, phone_number, email, investment_amount, details)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *;  -- Optional: Return inserted row if you want
    `;

    try {
        const { rows } = await db.query(query, [first_name, last_name, phone_country_code, phone_number, email, investment_amount, details || ""]);

        res.status(201).json({
            message: "Investment submitted successfully!",
            investmentId: rows[0].id, // Return inserted investment ID (you can also return other details)
        });
    } catch (err) {
        console.error("❌ Database error:", err);
        res.status(500).json({ error: "Database error" });
    }
});




// ✅ Get All Investments (Admin Only)
app.get('/api/investments', authenticateJWT, checkRole('admin'), async (req, res) => {
    console.log("✅ Admin access granted to /api/investments");

    const query = 'SELECT * FROM investments';

    try {
        const { rows } = await db.query(query);

        res.status(200).json({
            message: 'Successfully fetched all investments',
            data: rows, // Send the data in a JSON object
        });
    } catch (err) {
        console.error('❌ Database error:', err);
        res.status(500).send({ error: 'Database error' });
    }
});
export default app;
