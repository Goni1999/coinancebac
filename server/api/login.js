import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import rateLimit from "express-rate-limit";
import crypto from "crypto"; // ✅ Correct import
import cookieParser from 'cookie-parser';
import { db } from './db.js';

dotenv.config();
const port = process.env.PORT || 5000;

const app = express();

// Trust proxy for rate limiting when behind proxy (Vercel, etc.)
app.set('trust proxy', true);

app.use(cookieParser());

// Fetch environment variables - Vercel handles these automatically
const SECRET_KEY = process.env.SECRET_KEY;
if (!SECRET_KEY) {
    console.warn("⚠️ WARNING: SECRET_KEY environment variable not set");
} 
const userOtpStore = {}; // { "user@example.com": { otp: "123456", expiresAt: timestamp, verified: false } }

const corsOptions = {
  origin: ['https://dashboard.coinance.co'], // Allow dashboard domain
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

// ✅ Login Rate Limiter

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 login requests per window
    message: "Too many login attempts, please try again later.",
    standardHeaders: true, // Return rate limit info in headers
    legacyHeaders: false, // Disable deprecated headers
    // Configure for serverless environment
    trustProxy: true,
    keyGenerator: (req) => {
        // Use x-forwarded-for or x-real-ip headers for rate limiting in serverless
        return req.ip || req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown';
    },
    skip: (req) => {
        // Skip rate limiting for localhost in development
        const ip = req.ip || req.headers['x-forwarded-for'] || req.headers['x-real-ip'];
        return ip === '127.0.0.1' || ip === '::1';
    }
  });
  const transporter = nodemailer.createTransport({
          host: process.env.SMTP_HOST || 'smtp.hostinger.com',
          port: process.env.SMTP_PORT || 465,
          secure: true, // Use SSL
          auth: {
              user: process.env.SMTP_USER || 'service@capital-trust.eu',
              pass: process.env.SMTP_PASSWORD || 'Service25##'
          }
      });



      const authenticateJWT = (req, res, next) => {
        // Try getting the token from cookies first
        let token = req.cookies?.sessionToken || req.headers.authorization?.split(" ")[1];
      
        if (!token) {
          return res.status(401).json({ error: "Unauthorized: No token provided" });
        }
      
        jwt.verify(token, SECRET_KEY, (err, decoded) => {
          if (err) {
            return res.status(403).json({ error: "Forbidden: Invalid token" });
          }
          req.userEmail = decoded.email; // Extract email from decoded JWT payload
          req.userId = decoded.id; // Extract user ID from token
          next();
        });
      };
      

// Function to send a verification email
const sendVerificationEmail = async (email, token) => {
    const verificationLink = `https://dashboard.coinance.co/emailverification?token=${token}`;
    
    // Debug email configuration
    console.log('📧 Email Configuration Debug:');
    console.log('  SMTP_HOST:', process.env.SMTP_HOST || 'smtp.hostinger.com');
    console.log('  SMTP_PORT:', process.env.SMTP_PORT || 465);
    console.log('  SMTP_USER:', process.env.SMTP_USER || 'service@capital-trust.eu');
    console.log('  SMTP_PASSWORD set:', !!(process.env.SMTP_PASSWORD || 'Service25##'));
    
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.hostinger.com',
        port: process.env.SMTP_PORT || 465,
        secure: true, // Use SSL
        auth: {
            user: process.env.SMTP_USER || 'support@coinance.co',
            pass: process.env.SMTP_PASSWORD || 'Zoja25##'
        }
    });
    
    const mailOptions = {
        from: process.env.SMTP_USER || "support@coinance.co",
        to: email,
        subject: "Verify Your Email - Coinance",
        html: `<p>Click the link below to verify your email:</p>
               <a href="${verificationLink}">Verify your email</a>`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Verification email sent to ${email}`);
};

app.post("/auth/login", cors(corsOptions), loginLimiter, async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const query = "SELECT id, first_name, last_name, email, role, password, kyc_verification, verification_token, two_factor_enabled FROM users WHERE email = $1";
    const result = await db.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Invalid email or password" });
    }

    const user = result.rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, name: `${user.first_name} ${user.last_name}`, role: user.role, kyc_verified: user.kyc_verification, tfa_enabled: user.two_factor_enabled },
      SECRET_KEY,
      { expiresIn: rememberMe ? "7d" : "1h" }
    );

    delete user.password;

    let redirectPath = user.two_factor_enabled ? "/twostepverification" : "/verifyemail";
    if (redirectPath === "/verifyemail") {
      await sendVerificationEmail(user.email, user.verification_token);
    }

    // Set token as HttpOnly, Secure cookie
    res.cookie("sessionToken", token, {
      httpOnly: true,   // Prevents JavaScript access
      secure: true,     // Only sent over HTTPS
      sameSite: "None", // Required for cross-site cookies
      maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000, // 7 days or 1 hour
    });

    res.json({ message: "Login successful", token, redirect: redirectPath, role: user.role, });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


app.get('/api/session', (req, res) => {
  const token = req.cookies.sessionToken; // Get token from the HttpOnly cookie
  console.log('Session token:', token);  // Log the token for debugging
  
  if (!token) {
    return res.status(401).json({ message: "No session found" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    res.json({ isAuthenticated: true, user: decoded });
  } catch (err) {
    res.status(401).json({ message: "Invalid session" });
  }
});

















// 🔹 API: Check Email Verification Status
app.post('/auth/verify-email', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    console.error('❌ Missing token in request body');
    return res.status(400).json({ error: 'Token is required' });
  }

  try {
    // Verify the token (assuming the database logic is correct)
    const result = await db.query('SELECT id FROM users WHERE verification_token = $1', [token]);

    if (result.rows.length === 0) {
      console.error('❌ Invalid or expired token');
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const userId = result.rows[0].id;
    
    // Update user status to 'emailverified' and enable two-factor authentication
    await db.query('UPDATE users SET role = $1, two_factor_enabled = $2 WHERE id = $3', ['emailverified', true, userId]);

    res.status(200).json({ success: true, message: 'Email verified successfully, two-factor authentication enabled!' });

  } catch (err) {
    console.error('❌ Error verifying email:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});



  app.get("/api/check-email", async (req, res) => {
    const { email } = req.query;
    if (!email) {
        return res.status(400).json({ error: "Email is required" });
    }
    try {

        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);    

        if (result.rows.length === 0) {
            console.error('❌ Invalid or expired token');
            return res.status(400).json({ error: 'Invalid or expired token' });
          }

        const userRole = result.rows[0].role;

        return res.json({ email, role: userRole });
    } catch (err) {
        console.error("Error checking email verification:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});






// 📌 API: Check User Role
app.get("/api/check-user-role", cors(corsOptions), authenticateJWT, async (req, res) => {
  try {
    const email = req.userEmail; // Extracted from JWT

    // Fetch the user's role from the database
    const result = await db.query("SELECT role FROM users WHERE email = $1", [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ role: result.rows[0].role });
  } catch (error) {
    console.error("❌ Error fetching user role:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});








const sendOtpEmail = async (email, otp) => {
    

    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.hostinger.com',
        port: process.env.SMTP_PORT || 465,
        secure: true, // Use SSL
        auth: {
            user: process.env.SMTP_USER || 'service@capital-trust.eu',
            pass: process.env.SMTP_PASSWORD || 'Service25##'
        }
    });
  
    const mailOptions = {
      from: process.env.SMTP_USER || "service@capital-trust.eu",
      to: email,
      subject: "Your Verification Code",
      text: `Your verification code is: ${otp}. This code will expire in 5 minutes.`,
    };
  
    await transporter.sendMail(mailOptions);
  };

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();
// 📌 API: Send OTP
app.post("/api/send-otp", cors(corsOptions), authenticateJWT, async (req, res) => {
  console.log("🔹 Incoming OTP request for:", req.userId); // Debug log
  const email = req.userEmail;
  
  if (!email) {
    console.error("❌ No email found in token!");
    return res.status(400).json({ message: "Email is required" });
  }

  const otp = generateOtp();
  userOtpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000, verified: false };

  try {
    console.log("📩 Sending OTP to:", email);
    await sendOtpEmail(email, otp);
    res.json({ message: "" });
  } catch (error) {
    console.error("", error);
    res.status(500).json({ message: "" });
  }
});


// 📌 API: Verify OTP
app.post("/api/verify-otp", cors(corsOptions), authenticateJWT, (req, res) => {
  const email = req.userEmail; // Extracted from JWT
  const { otp } = req.body;
  const userOtp = userOtpStore[email];

  if (!userOtp) return res.status(400).json({ message: "not valid" });
  if (userOtp.expiresAt < Date.now()) return res.status(400).json({ message: "expire" });
  if (userOtp.otp !== otp) return res.status(400).json({ message: "false" });

  userOtpStore[email].verified = true;
  res.json({ message: "true" });
});

// 📌 API: Check OTP Status
app.get("/api/check-otp-status", authenticateJWT, (req, res) => {
  const email = req.userEmail; // Extracted from JWT
  const userOtpData = userOtpStore[email];

  res.json({ verified: userOtpData?.verified || false });
});
  

app.get("/api/check-kyc-status", cors(corsOptions), authenticateJWT, async (req, res) => {
  try {
    const email = req.userEmail; // Extracted from JWT

    // Fetch the user's KYC verification status from the database
     
    const result = await db.query('SELECT kyc_verification FROM users WHERE email = $1', [email]);    

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ kyc_verified: result.rows[0].kyc_verification || false });
  } catch (error) {
    console.error("Error fetching KYC status:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});



app.get("/api/get-user-data", cors(corsOptions), authenticateJWT, async (req, res) => {
  try {
    const email = req.userEmail; // Extracted from JWT

    // Fetch user data by email
    const result = await db.query(
      `SELECT id, first_name, last_name, date_of_birth, address, city, state, zip_code,
      identification_documents_type, identification_documents, kyc_verification, email, phone, position,
      card_id, facebook_link, xcom_link, linkedin_link, instagram_link, two_factor_enabled, role, gender
      FROM users WHERE email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});



// 🔹 API: Resend Verification Email
app.post('/api/resend-verification', cors(corsOptions), async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: "Email is required" });
        }

        const query = 'SELECT * FROM users WHERE email = $1';
        const result = await db.query(query, [email]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Email not found" });
        }

        const role = result.rows[0].role;
        const dbtoken = result.rows[0].verification_token;
        if (role !== "unverified") {
            return res.status(400).json({ error: "Email is already verified or ineligible for verification" });
        }


        await sendVerificationEmail(email, dbtoken);

        res.json({ message: "Verification email sent. Please check your inbox." });

    } catch (err) {
        console.error("Resend Email Error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});


app.post("/api/logout", cors(corsOptions), authenticateJWT , (req, res) => {
  try {
    const email = req.userEmail; // Extracted from JWT
    
    if (!email) {
      return res.status(400).json({ message: "User not found or not logged in" });
    }

    // Remove user from OTP store
    delete userOtpStore[email];

    // If using sessions, destroy it
    if (req.session) {
      res.clearCookie('sessionToken', { httpOnly: true, secure: true, sameSite: 'None' });
      req.session.destroy();
    }

    res.status(200).json({ message: "Successfully signed out" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});



// Function to send a verification email
const sendResetPassword = async (email, resetToken) => {
    const resetLink = `https://dashboard.coinance.co/resetpassword?token=${resetToken}`;
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.hostinger.com',
      port: process.env.SMTP_PORT || 465,
      secure: true, // Use SSL
      auth: {
          user: process.env.SMTP_USER || 'service@capital-trust.eu',
          pass: process.env.SMTP_PASSWORD || 'Service25##'
      }
  });
    const mailOptions = {
        from: process.env.SMTP_USER || "service@capital-trust.eu",
        to: email,
        subject: "Password Reset",
        html: `Click here to reset your password: ${resetLink}`,
    };

    await transporter.sendMail(mailOptions);
};





app.post("/api/request-password-reset", cors(corsOptions), async (req, res) => {
  console.log("Password reset endpoint called with:", req.method, req.url);
  
  // Ensure CORS headers are always set
  res.header('Access-Control-Allow-Origin', 'https://dashboard.coinance.co');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  const { email } = req.body;
  console.log("Received email:", email);
  
  // Validate email is provided
  if (!email) {
    console.log("❌ No email provided");
    return res.status(400).json({ message: "Email is required" });
  }
  
  try {
      // Start timer for timeout handling
      const startTime = Date.now();
      
      // Check if user exists with timeout
      const userPromise = db.query("SELECT id FROM users WHERE email = $1", [email]);
      const user = await Promise.race([
          userPromise,
          new Promise((_, reject) => 
              setTimeout(() => reject(new Error('Database query timeout')), 10000)
          )
      ]);
      
      if (user.rowCount === 0) {
          return res.status(404).json({ message: "User not found" });
      }

      // Generate secure token
      const resetToken = crypto.randomBytes(32).toString("hex");
      const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); 

      console.log("Generated token for password reset");

      // Store token in DB with timeout
      const updatePromise = db.query(
          "UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3 RETURNING *",
          [hashedToken, expiresAt, email]
      );
      
      const updateResult = await Promise.race([
          updatePromise,
          new Promise((_, reject) => 
              setTimeout(() => reject(new Error('Database update timeout')), 10000)
          )
      ]);

      if (updateResult.rowCount === 0) {
          return res.status(500).json({ message: "Failed to update reset token" });
      }

      // Send response first to avoid timeout, then send email asynchronously
      res.json({ message: "Password reset email sent" });
      
      // Send email asynchronously without blocking response
      setImmediate(async () => {
          try {
              await sendResetPassword(email, resetToken);
              console.log("✅ Password reset email sent successfully");
          } catch (emailError) {
              console.error("❌ Email sending failed:", emailError.message);
              // Don't throw error since response was already sent
          }
      });

  } catch (error) {
      console.error("❌ Password reset error:", error);
      // Ensure CORS headers on error responses
      res.header('Access-Control-Allow-Origin', 'https://dashboard.coinance.co');
      res.header('Access-Control-Allow-Credentials', 'true');
      
      if (error.message.includes('timeout')) {
          res.status(408).json({ message: "Request timeout, please try again" });
      } else {
          res.status(500).json({ message: "Server error", error: error.message });
      }
  }
});

  


app.post("/api/reset-password", cors(corsOptions), async (req, res) => {
  const { token, password } = req.body;

  try {
    if (!token || !password) {
      return res.status(400).json({ message: "Missing token or password" });
    }

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    console.log("Hashed Token:", hashedToken); // Debug hashed token

    // Find user with valid token
    const user = await db.query(
      "SELECT id FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()",
      [hashedToken]
    );
    
    console.log("User result:", user.rows); // Debug user result

    if (user.rowCount === 0) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update password & clear reset token
    await db.query(
      "UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2",
      [hashedPassword, user.rows[0].id]
    );

    res.json({ message: "Password reset successfully" });

  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});


  // Function to send a verification email
const sendAccAction = async (email, action) => {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.hostinger.com',
    port: process.env.SMTP_PORT || 465,
    secure: true, // Use SSL
    auth: {
        user: process.env.SMTP_USER || 'service@capital-trust.eu',
        pass: process.env.SMTP_PASSWORD || 'Service25##'
    }
});
  const mailOptions = {
      from: process.env.SMTP_USER || "service@capital-trust.eu",
      to: process.env.SMTP_USER || "service@capital-trust.eu",
      subject: "Account action to take",
      html: `User ${email} has requested to ${action} their account. Please review the request.`,
  };

  await transporter.sendMail(mailOptions);
};


app.post("/api/request-account-action", cors(corsOptions), async (req, res) => {
  try {
    const { email, action } = req.body;

    // Validate required fields
    if (!email || !action) {
      return res.status(400).json({ message: "Email and action are required." });
    }

    // Validate action type
    if (!["disable", "delete"].includes(action)) {
      return res.status(400).json({ message: "Invalid action type." });
    }

    await sendAccAction(email, action);

    res.status(200).json({ message: `Request to ${action.toUpperCase()} account sent successfully.` });
  } catch (error) {
    console.error("Error processing account request:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});




app.get("/api/transactions", cors(corsOptions), authenticateJWT, async (req, res) => {
  try {
    const userId = req.userId; // Extracted from JWT

    // Fetch transactions for the authenticated user using userId
    const transactionQuery = `
      SELECT time, type, balance_id, coin, amount, destination, txid, status 
      FROM transactions 
      WHERE user_id = $1
      ORDER BY time DESC`; // Fetch all transactions for the user, ordered by time (latest first)

    const result = await db.query(transactionQuery, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "No transactions found for this user" });
    }

    // Return the transactions for the user
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching transactions:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});




app.put("/api/update-user-data", cors(corsOptions), authenticateJWT, async (req, res) => {
  const { instagram, facebook, linkedin, xcom } = req.body;

  // Extract email from the authenticated user object (set by the authenticateJWT middleware)
  const email = req.userEmail;

  if (!email) {
    return res.status(400).json({ message: "Email not found in token" });
  }

  // Validate the input data
  if (!instagram && !facebook && !linkedin && !xcom) {
    return res.status(400).json({ message: "No social links provided to update" });
  }

  try {
    // Construct the query dynamically based on available fields
    const updatedFields = [];
    const values = [];
    let query = "UPDATE users SET";

    // Adding the social links dynamically
    if (instagram) {
      updatedFields.push("instagram_link = $" + (values.length + 1));
      values.push(instagram);
    }
    if (facebook) {
      updatedFields.push("facebook_link = $" + (values.length + 1));
      values.push(facebook);
    }
    if (linkedin) {
      updatedFields.push("linkedin_link = $" + (values.length + 1));
      values.push(linkedin);
    }
    if (xcom) {
      updatedFields.push("xcom_link = $" + (values.length + 1));
      values.push(xcom);
    }

    // Ensure we add the WHERE clause
    query += " " + updatedFields.join(", ") + " WHERE email = $" + (values.length + 1) + " RETURNING *";
    values.push(email); // Add email to the query values for the WHERE clause

    // Execute the query to update the social links
    const result = await db.query(query, values);

    // Check if the update was successful
    if (result.rowCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    // Respond with the updated user data
    res.json({ message: "Social links updated successfully"});
  } catch (error) {
    console.error("Error updating social links:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});



app.get('/api/balance', cors(corsOptions), authenticateJWT, async (req, res) => {
  const userId = req.userId;

  try {
    // Query to get the user's balance data from the database
    const query = `
      SELECT
        bitcoin, ethereum, xrp, tether, bnb, solana, usdc, dogecoin, cardano, staked_ether 
      FROM balance
      WHERE user_id = $1 AND status = 'Active';
    `;
    
    // Execute the query with the user's ID
    const result = await db.query(query, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Balance not found for user' });
    }

    // Send the balance data back as a response
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching user balance from database:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/coins', cors(corsOptions), authenticateJWT, async (req, res) => {
  const userId = req.userId;

  try {
    // Query to get the user's balance data from the database
    const query = `
      SELECT
        bitcoin, ethereum, xrp, tether, bnb, solana, usdc, dogecoin, cardano, staked_ether, usdt_total 
      FROM balance
      WHERE user_id = $1 AND status = 'Active';
    `;
    
    // Execute the query with the user's ID
    const result = await db.query(query, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Balance not found for user' });
    }

    // Send the balance data back as a response
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching user balance from database:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/profit', cors(corsOptions), authenticateJWT, async (req, res) => {
  const userId = req.userId;

  try {
    // Query to get the user's balance data from the database
    const query = `
      SELECT
        bitcoin, ethereum, xrp, tether, bnb, solana, usdc, dogecoin, cardano,
        staked_ether, usdt_total, unpaid_amount
      FROM balance
      WHERE user_id = $1 AND status = 'Active';
    `;
    
    // Execute the query with the user's ID
    const result = await db.query(query, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Balance not found for user' });
    }

    // Send the balance data back as a response
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching user balance from database:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.get('/api/invoices', cors(corsOptions), authenticateJWT, async (req, res) => {
  try {
    const userId = req.userId;

    // Query the database to fetch invoices for the authenticated user
    const result = await db.query(
      'SELECT * FROM invoices WHERE user_id = $1 ORDER BY issued_date DESC',
      [userId]
    );

    // Check if invoices are found
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No invoices found.' });
    }

    // Return the invoices to the frontend
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching invoices:', error);
    res.status(500).json({ error: 'An error occurred while fetching invoices.' });
  }
});





app.get('/api/events', cors(corsOptions), authenticateJWT, async (req, res) => {
  try {
    const userId = req.userId;

    console.log('Fetching Events for User:', { userId });

    // Use $1 for the placeholder in PostgreSQL
    const result = await db.query('SELECT * FROM events WHERE user_id = $1', [userId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'No events found' });
    }

    res.json(result.rows); // Return events from rows
  } catch (err) {
    console.error('Error fetching events:', err);  // Log the error for debugging
    res.status(500).json({ error: 'Error fetching events', details: err.message });
  }
});


app.post('/api/events', cors(corsOptions), authenticateJWT, async (req, res) => {
  const { title, start_date, end_date, level } = req.body;
  const userId = req.userId;

  console.log('Inserting Event:', { userId, title, start_date, end_date, level });

  try {
    // PostgreSQL uses $1, $2, ... placeholders instead of ?
    const result = await db.query(
      'INSERT INTO events (user_id, title, start_date, end_date, level) VALUES ($1, $2, $3, $4, $5) RETURNING id, title, start_date, end_date, level',
      [userId, title, start_date, end_date, level]
    );

    if (result.rowCount === 0) {
      return res.status(400).json({ error: 'Failed to save event' });
    }

    // Return the event details after insertion
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error saving event:', err);  // Log the error for debugging
    res.status(500).json({ error: 'Error saving event', details: err.message });
  }
});

app.put('/api/events', cors(corsOptions), authenticateJWT, async (req, res) => {
  const { id, title, start_date, end_date, level } = req.body; // Get id from body instead of params
  const userId = req.userId;

  console.log('Updating Event:', { id, title, start_date, end_date, level, userId });

  try {
    // Use $1, $2, $3, etc., for parameterized queries
    const result = await db.query(
      'UPDATE events SET title = $1, start_date = $2, end_date = $3, level = $4 WHERE id = $5 AND user_id = $6 RETURNING id, title, start_date, end_date, level',
      [title, start_date, end_date, level, id, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Event not found' });
    }

    // Return the updated event
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating event:', err);  // Log the error for debugging
    res.status(500).json({ error: 'Error updating event', details: err.message });
  }
});

app.delete('/api/events', cors(corsOptions), authenticateJWT, async (req, res) => {
  const { id } = req.body;  // Get id from body instead of params
  const userId = req.userId;

  console.log('Deleting Event:', { id, userId });

  try {
    // Use $1 and $2 for placeholders
    const result = await db.query(
      'DELETE FROM events WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Event not found' });
    }

    // If event is deleted, return a success message
    res.json({ message: 'Event deleted' });
  } catch (err) {
    console.error('Error deleting event:', err);  // Log the error for debugging
    res.status(500).json({ error: 'Error deleting event', details: err.message });
  }
});



app.post('/api/update-coins', cors(corsOptions), authenticateJWT, async (req, res) => {
  try {
    const userId = req.userId;  // Get userId from the JWT authentication middleware
    const { fromCoin, toCoin, fromAmount, toAmount } = req.body;

    // Check if the necessary data is provided
    if (!fromCoin || !toCoin || fromAmount === undefined || toAmount === undefined) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }

    // Query the balance table to get the current coin balances for the user
    const userBalanceQuery = await db.query(
      'SELECT * FROM balance WHERE user_id = $1',
      [userId]
    );

    // If no balance is found for the user, return an error
    if (userBalanceQuery.rows.length === 0) {
      return res.status(404).json({ error: 'User balance not found.' });
    }

    const userBalance = userBalanceQuery.rows[0];

    // Check if the user has sufficient funds of the `fromCoin`
    if (userBalance[fromCoin] < fromAmount) {
      return res.status(400).json({ error: 'Insufficient funds for the transaction.' });
    }

    // Start the transaction: subtract from the `fromCoin` and add to the `toCoin`
    await db.query('BEGIN');  // Begin the transaction

    // Update the `fromCoin` balance by subtracting the amount
    await db.query(
      `UPDATE balance SET ${fromCoin} = ${fromCoin} - $1, last_updated = CURRENT_TIMESTAMP WHERE user_id = $2`,
      [fromAmount, userId]
    );

    // Update the `toCoin` balance by adding the amount
    await db.query(
      `UPDATE balance SET ${toCoin} = ${toCoin} + $1, last_updated = CURRENT_TIMESTAMP WHERE user_id = $2`,
      [toAmount, userId]
    );

    // Create the transaction record
    const balanceIdQuery = await db.query(
      'SELECT balance_id FROM balance WHERE user_id = $1',
      [userId]
    );

    const balanceId = balanceIdQuery.rows[0].balance_id;
    const txid = `TXID${(Math.floor(Math.random() * 1000000) + 1).toString().padStart(6, '0')}`;
    const details = `Withdraw of ${fromAmount} ${fromCoin.toUpperCase()} to ${toAmount} ${toCoin.toUpperCase()}`;

    await db.query(
      'INSERT INTO transactions (user_id, balance_id, time, type, coin, amount, destination, txid, status, details) VALUES ($1, $2, CURRENT_TIMESTAMP, $3, $4, $5, $6, $7, $8, $9)',
      [
        userId,
        balanceId,
        'Withdraw',
        fromCoin.toUpperCase(),
        fromAmount,
        balanceId,
        txid,
        'Success',
        details,
      ]
    );

    // Commit the transaction
    await db.query('COMMIT');

    // Optionally, you can return the updated balance to the frontend
    const updatedBalanceQuery = await db.query(
      'SELECT * FROM balance WHERE user_id = $1',
      [userId]
    );

    res.json(updatedBalanceQuery.rows[0]);  // Return the updated user balance

  } catch (error) {
    console.error('Error updating coin balances:', error);
    await db.query('ROLLBACK');  // Rollback in case of error
    res.status(500).json({ error: 'An error occurred while updating coin balances.' });
  }
});




app.get('/api/wallet', cors(corsOptions), authenticateJWT, async (req, res) => {
  const userId = req.userId;

  try {
    // Query to get the user's balance data from the database
    const query = `
      SELECT balance_id 
      FROM balance
      WHERE user_id = $1;
    `;
    
    // Execute the query with the user's ID
    const result = await db.query(query, [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Balance not found for user' });
    }

    // Send the balance data back as a response
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching user balance from database:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});



export default app;