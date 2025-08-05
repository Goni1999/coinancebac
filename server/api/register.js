import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import dotenv from 'dotenv';
import cors from 'cors'; // Import cors here
import multer from 'multer'; // Use import
import path from 'path'; // Use import
import fs from 'fs'; // Use import
import cloudinary from 'cloudinary';
import { db } from './db.js';

dotenv.config();
const port = process.env.PORT || 5000;

const app = express();

// Ensure SECRET_KEY exists in .env
if (!process.env.SECRET_KEY) {
    console.warn("⚠️ WARNING: SECRET_KEY environment variable not set");
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


const corsOptions = {
    origin: 'https://dashboard.coinance.co', // Dashboard domain
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Include OPTIONS for preflight
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'], // Allow specific headers
    credentials: true, // Allow cookies and credentials to be sent
    optionsSuccessStatus: 200 // Some legacy browsers choke on 204
  };

// Handle OPTIONS requests first, before any other middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url} - Origin: ${req.headers.origin}`);
  
  // Set CORS headers for all requests
  res.header('Access-Control-Allow-Origin', 'https://dashboard.coinance.co');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight OPTIONS requests
  if (req.method === 'OPTIONS') {
    console.log('OPTIONS request handled');
    return res.status(200).end();
  }
  
  next();
});

app.use(cors(corsOptions));

app.use(express.json());

// Global error handler to ensure CORS headers on all responses
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  res.header('Access-Control-Allow-Origin', 'https://dashboard.coinance.co');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.status(500).json({ message: 'Internal server error' });
});




      const authenticateJWT = (req, res, next) => {
        const token = req.headers.authorization?.split(" ")[1]; // Extract token from Authorization header
      
        if (!token) {
          return res.status(403).json({ message: "No token provided" });
        }
      
        jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
          if (err) {
            return res.status(403).json({ message: "Invalid or expired token" });
          }
      
          req.userEmail = decoded.email; // Extract email from decoded JWT payload
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


app.post('/auth/register', cors(corsOptions), async (req, res) => {
  const { first_name, last_name, email, phone, password, confirmPassword, birthday, gender, address, city, state, zip_code, identification_documents_type, card_id, position } = req.body;

  if (!first_name || !last_name || !email || !password || !birthday || !address || !city || !state || !zip_code || !identification_documents_type || !phone || !position || !card_id || !gender) {
      return res.status(400).json({
          error: 'All fields are required',
          missing: ['first_name', 'last_name', 'email', 'password', 'gender', 'birthday', 'address', 'city', 'state', 'zip_code', 'identification_documents_type',  'phone', 'position', 'card_id'].filter(f => !req.body[f])
      });
  }

  try {
      // Hash the password using bcrypt
      const hashedPassword = await bcrypt.hash(password, 10);
      
      // Generate a unique verification token
      const verification_token = crypto.randomBytes(32).toString('hex');
      
      // Insert the user into the database with the required fields
      const query = `INSERT INTO users 
                     (id, first_name, last_name, email, password, date_of_birth, address, city, state, zip_code, identification_documents_type,  phone, position, card_id,  verification_token, gender, role)
                     VALUES 
                     (LPAD(nextval('user_id_seq')::text, 7, '0'), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'unverified') 
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
          verification_token,
          gender
      ]);

      if (result.rows.length > 0) {
          const userId = result.rows[0].id;
          
          

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








app.post('/auth/send-verification-email', cors(corsOptions), async (req, res) => {
    const { userId, email, verification_token } = req.body;

    if (!userId || !email || !verification_token) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        // Send the verification email
        const transporter = nodemailer.createTransport({
          host: 'smtp.hostinger.com',
          port: 465,
          auth: {
              user: process.env.SMTP_USER || 'service@capital-trust.eu',
              pass: process.env.SMTP_PASSWORD || 'Service25##'
          }
      });

        const verificationLink = `https://coinance.co/verify-email?token=${verification_token}`;
        const mailOptions = {
            from: process.env.SMTP_USER || 'service@capital-trust.eu',
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
const sendKycEmail = async (email, imageUrls) => {
    try {
      const transporter = nodemailer.createTransport({
        host: 'smtp.hostinger.com',
        port: 465,
                auth: {
            user: process.env.SMTP_USER || 'service@capital-trust.eu',
            pass: process.env.SMTP_PASSWORD || 'Service25##'
        }
    });

    const mailOptions = {
        from: process.env.SMTP_USER || 'service@capital-trust.eu',
        to: process.env.SMTP_USER || 'service@capital-trust.eu',
        subject: 'New KYC Verification Submission',
        text: `The KYC files have been uploaded for user with email ${email}. Here are the links to the uploaded photos:\n\n${imageUrls.join('\n')}`,
      };
  
      await transporter.sendMail(mailOptions);
      console.log('Email sent successfully');
      return true; // Email sent successfully
    } catch (err) {
      throw new Error('Error sending KYC email');
    }
  };
  
  app.post('/auth/save-kyc', cors(corsOptions), authenticateJWT, async (req, res) => {
    const { urls } = req.body; // KYC image URLs sent from the frontend
    const token = req.headers.authorization?.split(' ')[1]; // Get the token from the Authorization header
    const email = req.userEmail; // Extracted from JWT

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
  
    try {
      // Decode the JWT token to get the user ID
     
  
      if (!urls || urls.length === 0) {
        return res.status(400).json({ error: 'No URLs provided for KYC' });
      }
  
      // Send the KYC email with the URLs
      await sendKycEmail(email, urls);
  
      // Update the user role to 'pending'
      await db.query(
        'UPDATE users SET role = $1, kyc_verification = $2 WHERE email = $3',
        ['pending', true, email]
      );
        
      // Respond with success
      res.status(200).json({ message: 'KYC URLs saved and email sent successfully' });
    } catch (error) {
      console.error('Error during KYC processing:', error);
      res.status(500).json({ error: 'Error saving KYC data or sending email' });
    }
  });

export default app;
