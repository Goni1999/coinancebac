import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pkg from 'pg';
import dotenv from 'dotenv';

dotenv.config();
const port = process.env.PORT || 5000;

const { Client } = pkg;

const app = express();

// Ensure SECRET_KEY exists in .env
if (!process.env.SECRET_KEY) {
    console.warn("⚠️ WARNING: SECRET_KEY environment variable not set");
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


app.get('/api/test-db-connection', async (req, res) => {
    try {
      // Attempt to connect to the database
      console.log('✅ Connected to PostgreSQL');
  
      // Test the connection with a simple query, like SELECT NOW() or SELECT version()
      const result = await db.query('SELECT NOW()');
      
      // Send success response with timestamp
      res.status(200).json({
        message: 'Database connection successful',
        timestamp: result.rows[0].now, // Current timestamp from the database
      });
    } catch (err) {
      console.error('Error connecting to PostgreSQL:', err);
      
      // Send error response if the connection fails
      res.status(500).json({
        message: 'Error connecting to database',
        error: err.message,
      });
    } finally {
      // Close the database connection
      await db.end();
    }
  });


// Add Cache-Control to prevent caching
app.get('/api/index', (req, res) => {
  res.set('Cache-Control', 'no-store'); // Disable caching to prevent 304 responses
  res.status(200).json({ message: 'Server is connected' });
});
// Token Generation





// ✅ Debugging Log to Check All Registered Routes
app._router.stack.forEach((route) => {
    if (route.route && route.route.path) {
        console.log(`🛠 Registered Route: ${route.route.path}`);
    }
});


export default app;
