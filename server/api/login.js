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



app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send({ error: 'All fields are required' });
    }

    const query = 'SELECT * FROM users WHERE email = $1';  // Use parameterized query for security
    db.query(query, [email], async (err, results) => {
        if (err) {
            return res.status(500).send({ error: 'Database error' });
        }

        if (results.rows.length === 0) {
            return res.status(404).send({ error: 'Invalid email or password' });
        }

        const user = results.rows[0];  // Get the user object from results

        // Verify the password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).send({ error: 'Invalid email or password' });
        }

        // Generate JWT token after password validation
        const token = jwt.sign(
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
            process.env.SECRET_KEY,  // Use the secret key from your environment
            { expiresIn: '1h' }  // Token expiration time (1 hour in this case)
        );

        // Send response with user data and token
        res.send({ message: 'Login successful', user, token });
    });
});


export default app;
