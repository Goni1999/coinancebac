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




app.put('/api/trade', authenticateJWT, (req, res) => {
    const { userId, fromCurrency, toCurrency, amount, conversionRate } = req.body;

    if (!userId || !fromCurrency || !toCurrency || !amount || !conversionRate) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Convert amount based on the exchange rate
    const convertedAmount = amount * conversionRate;

    // Ensure user has enough balance to trade
    const checkBalanceQuery = `SELECT ${fromCurrency} FROM users WHERE id = $1`;
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
            WHERE id = $1
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

export default app;
