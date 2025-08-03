import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { Client } from 'pg';
import dotenv from 'dotenv';

dotenv.config();
const port = process.env.PORT || 5000;

const app = express();

// Ensure SECRET_KEY exists in .env
if (!process.env.SECRET_KEY) {
    console.warn("⚠️ WARNING: SECRET_KEY environment variable not set");
}

// Fetch environment variables
const SECRET_KEY = process.env.SECRET_KEY;

// Database connection using Neon PostgreSQL URL from .env
const db = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
});

const corsOptions = {
    origin: 'https://coinance.co', // Update this to your frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};

app.use(cors(corsOptions));

app.use(express.json());

// Connect to the PostgreSQL database
const connectDB = async () => {
    try {
        await db.connect();
        console.log('✅ Connected to PostgreSQL');
    } catch (err) {
        console.error('Error connecting to PostgreSQL:', err);
        setTimeout(connectDB, 5000); // Retry after 5 seconds
    }
};

connectDB();

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).send({ error: 'Unauthorized: No token provided' });
    }

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).send({ error: 'Unauthorized: Invalid or expired token' });
        }

        req.user = user;
        next();
    });
};


app.post('/api/trade', async (req, res) => {
    const { userId, fromCurrency, toCurrency, amount, fee, convertedAmount } = req.body;

    try {
        // 1. Validate incoming data
        if (!userId ||  !amount || !fee || !convertedAmount) {
            return res.status(400).json({ error: 'Missing required fields.' });
        }

        // 2. Fetch the user from the database
        const userResult = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
        const user = userResult.rows[0];

        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // 3. Check if the user has enough balance for the `fromCurrency`
        if (user[fromCurrency] < amount) {
            return res.status(400).json({ error: `Not enough ${fromCurrency} balance to complete the trade.` });
        }

        // 4. Update the user's balances
        // Update the fromCurrency (set it to the new amount)
        const updateFromCurrencyQuery = `
            UPDATE users
            SET ${fromCurrency} = $1
            WHERE id = $2
        `;
        await db.query(updateFromCurrencyQuery, [amount, userId]);

        // Update the toCurrency (increment by the converted amount)
        const updateToCurrencyQuery = `
    UPDATE users
    SET ${toCurrency} = COALESCE(${toCurrency}, 0) + $1
    WHERE id = $2
`;

await db.query(updateToCurrencyQuery, [convertedAmount, userId]);


        // 5. Update the total fee (add fee to the current total)
        const updateTotalQuery = `
            UPDATE users
            SET total = total + $1
            WHERE id = $2
        `;
        await db.query(updateTotalQuery, [fee, userId]);

        // 6. Send a success response
        res.status(200).json({ message: 'Trade completed successfully.' });

    } catch (error) {
        console.error('❌ Error processing trade:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});


export default app;

