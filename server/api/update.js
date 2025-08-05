
  import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { db } from './db.js';

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
  
  
  app.post('/api/update-balances', authenticateJWT, checkRole('admin'), async (req, res) => {
    const { users } = req.body;  // Receive array of users from frontend

    console.log("Received users data:", users);

    if (!Array.isArray(users) || users.length === 0) {
        return res.status(400).json({ error: 'Invalid user data provided' });
    }

    try {
        await db.query('BEGIN');  // Start a database transaction

        // Iterate over each user in the provided array
        for (const user of users) {
            const { userId, balances, total } = user;

            // Prepare the dynamic SET clause and the values for the query
            const setFields = [];
            const values = [];

            // Add fields to update based on the provided balances
            if (balances.BTC !== undefined) {
                setFields.push('BTC = $' + (setFields.length + 1));
                values.push(balances.BTC);
            }
            if (balances.ETH !== undefined) {
                setFields.push('ETH = $' + (setFields.length + 1));
                values.push(balances.ETH);
            }
            if (balances.ADA !== undefined) {
                setFields.push('ADA = $' + (setFields.length + 1));
                values.push(balances.ADA);
            }
            if (balances.XRP !== undefined) {
                setFields.push('XRP = $' + (setFields.length + 1));
                values.push(balances.XRP);
            }
            if (balances.DOGE !== undefined) {
                setFields.push('DOGE = $' + (setFields.length + 1));
                values.push(balances.DOGE);
            }
            if (balances.BNB !== undefined) {
                setFields.push('BNB = $' + (setFields.length + 1));
                values.push(balances.BNB);
            }
            if (balances.SOL !== undefined) {
                setFields.push('SOL = $' + (setFields.length + 1));
                values.push(balances.SOL);
            }
            if (balances.DOT !== undefined) {
                setFields.push('DOT = $' + (setFields.length + 1));
                values.push(balances.DOT);
            }

            // Always update the total field
            setFields.push('total = $' + (setFields.length + 1));
            values.push(total);

            // Add the user ID at the end of the values array (this is for the WHERE clause)
            const userIdIndex = setFields.length + 1; // this will be the position of userId in the values array
            values.push(userId);

            // Build the full query dynamically
            const updateQuery = `
                UPDATE users
                SET ${setFields.join(', ')}
                WHERE id = $${userIdIndex}
            `;

            // Execute the update query with dynamic values
            await db.query(updateQuery, values);
        }

        await db.query('COMMIT');  // Commit the transaction after all updates
        res.status(200).json({ message: 'User balances updated successfully!' });
    } catch (err) {
        await db.query('ROLLBACK');  // Rollback the transaction in case of error
        console.error('❌ Error updating users:', err);
        res.status(500).json({ error: 'Failed to update user balances' });
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
