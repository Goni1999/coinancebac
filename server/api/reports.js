import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { db, connectDB } from './db.js';

dotenv.config();
const port = process.env.PORT || 5000;

const app = express();

// Ensure SECRET_KEY exists in .env
if (!process.env.SECRET_KEY) {
    console.warn("⚠️ WARNING: SECRET_KEY environment variable not set");
}

// Fetch environment variables
const SECRET_KEY = process.env.SECRET_KEY; 

const corsOptions = {
    origin: 'https://coinance.co', // Replace with your frontend domain
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allow specific HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'], // Allow specific headers
  };

app.use(cors(corsOptions));
app.use(express.json());

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

app.get('/api/reports', authenticateJWT, checkRole('admin'), async (req, res) => {
    console.log("✅ Admin access granted to /api/reports");

    const query = 'SELECT * FROM reports;';  // Fetch all reports

    try {
        const { rows } = await db.query(query);  // Query reports from the database

        if (rows.length === 0) {
            return res.status(404).send({ error: 'No reports found' });
        }

        res.status(200).json({
            message: 'Successfully fetched all reports',
            data: rows,  // Send the reports in 'data' field
        });
    } catch (err) {
        console.error("❌ Database error:", err);
        res.status(500).send({ error: 'Database error' });
    }
});

app.post('/api/reports', (req, res) => {
    const { name, surname, email, description } = req.body;

    if (!name || !surname || !email || !description) {
        return res.status(400).json({ error: "All fields are required" });
    }

    const query = `
        INSERT INTO reports (name, surname, email, description, created_at)
        VALUES ($1, $2, $3, $4, NOW())
    `;

    db.query(query, [name, surname, email, description], (err, result) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.status(201).json({ message: "Report submitted successfully!", reportId: result.insertId });
    });
});

export default app;
