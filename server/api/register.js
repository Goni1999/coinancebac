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
    origin: 'https://reactfrontend-de12345.netlify.app', // Replace with your frontend domain
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


// this is the fixed part of code for register, make the changes in others part of code to work properly as this one 
app.post('/auth/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({
            error: 'All fields are required',
            missing: ['name', 'email', 'password'].filter(f => !req.body[f])
        });
    }

    try {
        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);
        // Create the query to insert a new user
        const query = 'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id';
        
        // Use async/await with db.query() for better result handling
        const result = await db.query(query, [name, email, hashedPassword, 'user']);

        // Check if the result is valid and return a response
        if (result.rows.length > 0) {
            const userId = result.rows[0].id; // Get the inserted user id
            return res.status(201).json({
                message: 'Registration successful',
                userId: userId,
                nextStep: '/auth/login'
            });
        }

        // If for any reason the insertion didn't work as expected
        return res.status(500).json({
            error: 'Registration failed',
            code: 'DB_ERROR'
        });
    } catch (err) {
        console.error("❌ Registration error:", err);
        res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
});
export default app;
