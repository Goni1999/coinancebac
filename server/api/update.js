
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
  
  
  app.put('/api/update-balances', authenticateJWT, checkRole('admin'), async (req, res) => {
    const { id, BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total } = req.body; // Extract `id` from request body

    // Validate that required fields are present
    if (!id || !BTC || !ETH || !ADA || !XRP || !DOGE || !BNB || !SOL || !DOT || !total) {
        return res.status(400).json({ error: "All balance fields and user ID are required" });
    }

    const query = `
        UPDATE users
        SET BTC = $1, ETH = $2, ADA = $3, XRP = $4, DOGE = $5, BNB = $6, SOL = $7, DOT = $8, total = $9
        WHERE id = $10;  
    `;

    try {
        const { rows } = await db.query(query, [BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total, id]); // Use `id` from request body
        
        if (rows.length === 0) {
            return res.status(404).send({ error: 'User not found' });
        }

        res.status(200).json({
            message: 'User updated successfully',
            updatedUser: rows[0] // Return the updated user object if necessary
        });
    } catch (err) {
        console.error("❌ Database error:", err);
        res.status(500).send({ error: 'Database error' });
    }
}); 
// ✅ Update User's Total Balance in `users` Table
app.put('/api/update-total/:id', authenticateJWT, (req, res) => {
    const userId = req.params.id;
    const { total } = req.body;

    if (!total || isNaN(total)) {
        return res.status(400).send({ error: "Invalid total value" });
    }

    const query = `UPDATE users SET total = $1 WHERE id = $2`;

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

export default app;
