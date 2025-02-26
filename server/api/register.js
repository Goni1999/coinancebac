import express from 'express';
import bcrypt from 'bcrypt';
import pkg from 'pg';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import dotenv from 'dotenv';
import cors from 'cors'; // Import cors here
const multer = require('multer');
const path = require('path');
const fs = require('fs'); // Required for file handling (storing temporarily)
import cloudinary from 'cloudinary';

dotenv.config();
const port = process.env.PORT || 5000;

const { Client } = pkg;

const app = express();

// Ensure SECRET_KEY exists in .env
if (!process.env.SECRET_KEY) {
    throw new Error("FATAL ERROR: SECRET_KEY is missing");
}
cloudinary.config({
    cloud_name: 'dqysonzsh',
    api_key: '262198945875427',
    api_secret: '-q9B9VNJjJojGVYiPvQ3pzWuVmI',
  });
  const upload = multer({ storage: multer.memoryStorage() }); // Store files in memory

// Fetch environment variables
const SECRET_KEY = process.env.SECRET_KEY;
const EMAIL_HOST = process.env.EMAIL_HOST;
const EMAIL_PORT = process.env.EMAIL_PORT;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;
const FRONTEND_URL = process.env.FRONTEND_URL;
// Database connection using Neon PostgreSQL URL from .env
const db = new Client({
    connectionString: process.env.DATABASE_URL, // Use DATABASE_URL from .env
    ssl: {
        rejectUnauthorized: false, // Necessary for SSL connections with Neon
    },
});

const corsOptions = {
    origin: 'https://dashboard-pied-psi.vercel.app', // Replace with your frontend domain
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

const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1]; // Extract token from Authorization header
  
    if (!token) {
      return res.status(403).json({ message: 'No token provided' });
    }
  
    jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid or expired token' });
      }
  
      req.userId = decoded.userId; // Assuming the userId is in the decoded JWT payload
      next();
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


app.post('/auth/register', async (req, res) => {
  const { first_name, last_name, email, password, birthday, address, city, state, zip_code, identification_documents_type,  phone, position, card_id } = req.body;

  if (!first_name || !last_name || !email || !password || !birthday || !address || !city || !state || !zip_code || !identification_documents_type || !phone || !position || !card_id) {
      return res.status(400).json({
          error: 'All fields are required',
          missing: ['first_name', 'last_name', 'email', 'password', 'birthday', 'address', 'city', 'state', 'zip_code', 'identification_documents_type',  'phone', 'position', 'card_id'].filter(f => !req.body[f])
      });
  }

  try {
      // Hash the password using bcrypt
      const hashedPassword = await bcrypt.hash(password, 10);
      
      // Generate a unique verification token
      const verification_token = crypto.randomBytes(32).toString('hex');
      
      // Insert the user into the database with the required fields
      const query = `INSERT INTO users 
                     (id, first_name, last_name, email, password, date_of_birth, address, city, state, zip_code, identification_documents_type,  phone, position, card_id,  verification_token)
                     VALUES 
                     (LPAD(nextval('user_id_seq')::text, 7, '0'), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) 
                     RETURNING id`;

      const result = await db.query(query, [
          first_name, 
          last_name, 
          email, 
          hashedPassword, 
          birthday, 
          address, 
          city, 
          state, 
          zip_code, 
          identification_documents_type, 
          phone, 
          position, 
          card_id, 
          verification_token
      ]);

      if (result.rows.length > 0) {
          const userId = result.rows[0].id;
          
          // Send verification code (this can be part of your email logic)
          // Generate a 6-digit code for email verification
          const verification_code = Math.floor(100000 + Math.random() * 900000); // Generates a 6-digit code

          // Send email logic here (you need to implement this)
          // Example: sendVerificationEmail(email, verification_code);

          return res.status(201).json({
              message: 'Registration successful! Please check your email to verify your account.',
        
          });
      }

      return res.status(500).json({ error: 'Registration failed', code: 'DB_ERROR' });
  } catch (err) {
      console.error('❌ Registration error:', err);
      res.status(500).json({ error: 'Internal server error', code: 'SERVER_ERROR' });
  }
});








app.post('/auth/send-verification-email', async (req, res) => {
    const { userId, email, verification_token } = req.body;

    if (!userId || !email || !verification_token) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        // Send the verification email
        const transporter = nodemailer.createTransport({
          host: 'smtp.titan.email',
          port: 465,
          auth: {
              user: 'info@royalpharm.io',
              pass: 'Royal25##'
          }
      });

        const verificationLink = `https://capital-trust.eu/verify-email?token=${verification_token}`;
        const mailOptions = {
            from: 'info@royalpharm.io',
            to: email,
            subject: 'Verify your email',
            text: `Please click the link below to verify your email address:\n\n${verificationLink}`,
        };

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.error('Error sending email:', err);
                return res.status(500).json({ error: 'Error sending email verification' });
            }
            console.log('Email sent: ' + info.response);  // Log email sending success
            return res.status(200).json({ message: 'Verification email sent successfully' });
        });
    } catch (err) {
        console.error('❌ Sending verification email error:', err);
        res.status(500).json({ error: 'Internal server error', code: 'SERVER_ERROR' });
    }
});
















  
  

  // Function to send KYC email with photo URLs
const sendKycEmail = async (userId, imageUrls) => {
    try {
        const transporter = nodemailer.createTransport({
            host: 'smtp.hostinger.com',
            port: 465,
            auth: {
                user: 'service@capital-trust.eu',
                pass: 'Service25##'
            }
        });
        
  
      const mailOptions = {
        from: 'service@capital-trust.eu',
        to: 'info@capital-trust.eu',
        subject: 'New KYC Verification Submission',
        text: `The KYC files have been uploaded for user with ID ${userId}. Here are the links to the uploaded photos:\n\n${imageUrls.join('\n')}`,
      };
  
      await transporter.sendMail(mailOptions);
      console.log('Email sent successfully');
      return true; // Email sent successfully
    } catch (err) {
      throw new Error('Error sending KYC email');
    }
  };
  
  app.post('/auth/save-kyc', authenticateJWT, async (req, res) => {
    const { urls } = req.body; // KYC image URLs sent from the frontend
    const token = req.headers.authorization?.split(' ')[1]; // Get the token from the Authorization header
  
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
  
    try {
      // Decode the JWT token to get the user ID
      const decodedToken = jwt.verify(token, process.env.SECRET_KEY); // Replace 'your_jwt_secret' with the secret key used for JWT
      const userId = decodedToken.id;
  
      if (!urls || urls.length === 0) {
        return res.status(400).json({ error: 'No URLs provided for KYC' });
      }
  
      // Send the KYC email with the URLs
      await sendKycEmail(userId, urls);
  
      // Update the user role to 'pending'
      await db.query('UPDATE users SET role = $1 WHERE id = $2', ['pending', userId]);
  
      // Respond with success
      res.status(200).json({ message: 'KYC URLs saved and email sent successfully' });
    } catch (error) {
      console.error('Error during KYC processing:', error);
      res.status(500).json({ error: 'Error saving KYC data or sending email' });
    }
  });

export default app;
