import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import pkg from 'pg';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import rateLimit from "express-rate-limit";

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
const userOtpStore = {}; // { "user@example.com": { otp: "123456", expiresAt: timestamp, verified: false } }

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
// ✅ Login Rate Limiter

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
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 login requests per window
    message: "Too many login attempts, please try again later.",
    standardHeaders: true, // Return rate limit info in headers
    legacyHeaders: false, // Disable deprecated headers
  });
  const transporter = nodemailer.createTransport({
          host: 'smtp.titan.email',
          port: 465,
          auth: {
              user: 'info@royalpharm.io',
              pass: 'Royal25##'
          }
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

// Function to send a verification email
const sendVerificationEmail = async (email, token) => {
    const verificationLink = `https://dashboard-pied-psi.vercel.app/emailverification?token=${token}`;
    
    const mailOptions = {
        from: "info@royalpharm.io",
        to: email,
        subject: "Verify Your Email - Capital Trust",
        html: `<p>Click the link below to verify your email:</p>
               <a href="${verificationLink}">Verify your email</a>`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Verification email sent to ${email}`);
};

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    if (!email || !password) return res.status(400).json({ error: "All fields are required" });

    const query = "SELECT id, first_name, last_name, email, role, password, kyc_verification, verification_token FROM users WHERE email = $1";
    const result = await db.query(query, [email]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Invalid email or password" });

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ error: "Invalid email or password" });

    const token = jwt.sign(
      { id: user.id, email: user.email, name: `${user.first_name} ${user.last_name}`, role: user.role, kyc_verified: user.kyc_verification },
      SECRET_KEY,
      { expiresIn: rememberMe ? "7d" : "1h" }
    );

    delete user.password;

    let redirectPath = "/twostepverification"; // Default

    if (user.role === "unverified") {
      let verificationToken = user.verification_token || crypto.randomBytes(32).toString("hex");
      if (!user.verification_token) {
        await db.query("UPDATE users SET verification_token = $1 WHERE email = $2", [verificationToken, user.email]);
      }
      await sendVerificationEmail(user.email, verificationToken);
      redirectPath = "/verifyemail";
    } else if (user.role !== "unverified") {
      redirectPath = "/twostepverification";
    }

    console.log("✅ Redirecting user to:", redirectPath); // ✅ Debug Log

    res.json({ message: "Login successful", token, redirect: redirectPath });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Internal server error" });
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
      const result = await db.query('SELECT * FROM users WHERE verification_token = $1', [token]);
  
      if (result.rows.length === 0) {
        console.error('❌ Invalid or expired token');
        return res.status(400).json({ error: 'Invalid or expired token' });
      }
  
      const userId = result.rows[0].id;
      
      // Update user status to 'verified'
      await db.query('UPDATE users SET role = $1 WHERE id = $2', ['emailverified', userId]);
  
      res.status(200).json({ success: true, message: 'Email verified successfully!' });
  
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














const sendOtpEmail = async (email, otp) => {
    

    const transporter = nodemailer.createTransport({
        host: 'smtp.titan.email',
        port: 465,
        auth: {
            user: 'info@royalpharm.io',
            pass: 'Royal25##'
        }
    });
  
    const mailOptions = {
      from: "info@royalpharm.io",
      to: email,
      subject: "Your Verification Code",
      text: `Your verification code is: ${otp}. This code will expire in 5 minutes.`,
    };
  
    await transporter.sendMail(mailOptions);
  };

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();
// 📌 API: Send OTP
app.post("/api/send-otp", authenticateJWT, async (req, res) => {
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
    res.json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error("❌ Error sending OTP:", error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
});


// 📌 API: Verify OTP
app.post("/api/verify-otp", authenticateJWT, (req, res) => {
  const email = req.userEmail; // Extracted from JWT
  const { otp } = req.body;
  const userOtp = userOtpStore[email];

  if (!userOtp) return res.status(400).json({ message: "No OTP found. Request a new one." });
  if (userOtp.expiresAt < Date.now()) return res.status(400).json({ message: "OTP expired." });
  if (userOtp.otp !== otp) return res.status(400).json({ message: "Invalid OTP." });

  userOtpStore[email].verified = true;
  res.json({ message: "OTP verified successfully" });
});

// 📌 API: Check OTP Status
app.get("/api/check-otp-status", authenticateJWT, (req, res) => {
  const email = req.userEmail; // Extracted from JWT
  const userOtpData = userOtpStore[email];

  res.json({ verified: userOtpData?.verified || false });
});
  

app.get("/api/check-kyc-status", authenticateJWT, async (req, res) => {
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







// 🔹 API: Resend Verification Email
app.post('/api/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: "Email is required" });
        }

        const query = 'SELECT role FROM users WHERE email = $1';
        const result = await db.query(query, [email]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Email not found" });
        }

        const role = result.rows[0].role;
        if (role !== "unverified") {
            return res.status(400).json({ error: "Email is already verified or ineligible for verification" });
        }

        const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '1h' });

        await sendVerificationEmail(email, token);

        res.json({ message: "Verification email sent. Please check your inbox." });

    } catch (err) {
        console.error("Resend Email Error:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});




export default app;