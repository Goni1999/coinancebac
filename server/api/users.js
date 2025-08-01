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


// ✅ Get All Users (Admin Only)
app.get('/api/users', authenticateJWT, checkRole('admin'), async (req, res) => {
    console.log("✅ Admin access granted to /api/users");

    // Log user information (helpful for debugging)
    console.log("✅ User info from JWT:", req.user);

    const query = `
        SELECT id, name, email, role, BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total
        FROM users;
    `;

    try {
        // Execute the query using the db client
        const { rows } = await db.query(query);  // Use db.query() instead of pool.query()

        // If no results found, return an appropriate response
        if (rows.length === 0) {
            return res.status(404).send({ error: 'No users found' });
        }

        // Send the rows of the result as the response
        res.status(200).send(rows);  // Access the rows property to get the actual data

    } catch (err) {
        // Log the error and send a 500 status code if there's a problem with the database query
        console.error("❌ Database error:", err);
        res.status(500).send({ error: 'Database error' });
    }
});


app.get('/api/users/:id', authenticateJWT, (req, res) => {
    const userId = req.params.id;
    console.log("🔍 Fetching user balances for ID:", userId);
  
    const query = `SELECT BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total FROM users WHERE id = $1`;
    db.query(query, [userId], (err, results) => {
      if (err) {
        console.error('❌ Database error:', err);
        return res.status(500).send({ error: 'Database error' });
      }
  
      if (results.length === 0) {
        console.warn("⚠️ No user found for ID:", userId);
        return res.status(404).json({ error: 'User not found' });
      }
  
      console.log("✅ User Balances:", results[0]);
      res.json(results[0]);
    });
  });
  
  app.post('/api/userss', authenticateJWT, async (req, res) => {
    const { id } = req.body; // Get the `id` from the request body
    
    console.log("🔍 Fetching user balances for ID:", id);
  
    const query = `
        SELECT BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total 
        FROM users 
        WHERE id = $1
    `;
    
    try {
      // Execute the query to find user by the provided ID
      const result = await db.query(query, [id]);
  
      // If no user found, return a 404 error
      if (result.rows.length === 0) {
        console.warn("⚠️ No user found for ID:", id);
        return res.status(404).json({ error: 'User not found' });
      }
  
      // Return the user balances
      console.log("✅ User Balances:", result.rows[0]);
      return res.status(200).json(result.rows[0]);  // Send the data for the user
    } catch (err) {
      console.error('❌ Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  

export default app;
