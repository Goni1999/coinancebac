import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import pkg from 'pg';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import crypto from "crypto";

dotenv.config();

const { Client } = pkg;

// Database connection
const db = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
});

// Connect to database
const connectDB = async () => {
    try {
        await db.connect();
        console.log('✅ Connected to PostgreSQL');
    } catch (err) {
        console.error('Error connecting to PostgreSQL:', err);
    }
};

// Function to send reset password email
const sendResetPassword = async (email, resetToken) => {
    const resetLink = `https://dashboard.coinance.co/resetpassword?token=${resetToken}`;
    const transporter = nodemailer.createTransporter({
        host: 'smtp.hostinger.com',
        port: 465,
        auth: {
            user: 'support@coinance.co',
            pass: 'Zoja25##'
        }
    });
    
    const mailOptions = {
        from: "support@coinance.co",
        to: email,
        subject: "Password Reset",
        html: `Click here to reset your password: ${resetLink}`,
    };

    await transporter.sendMail(mailOptions);
};

// Main handler function
export default async function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', 'https://dashboard.coinance.co');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    // Handle preflight OPTIONS request
    if (req.method === 'OPTIONS') {
        console.log('OPTIONS request handled for password reset');
        return res.status(200).end();
    }

    // Only allow POST method
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method not allowed' });
    }

    console.log('Password reset request received:', req.method, req.url);

    try {
        // Connect to database if not already connected
        if (!db._connected) {
            await connectDB();
        }

        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: "Email is required" });
        }

        // Check if user exists
        const user = await db.query("SELECT id FROM users WHERE email = $1", [email]);
        if (user.rowCount === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        // Generate secure token
        const resetToken = crypto.randomBytes(32).toString("hex");
        const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

        console.log("Token:", resetToken);
        console.log("Hashed Token:", hashedToken);
        console.log("Expiry:", expiresAt);

        // Store token in DB
        const updateResult = await db.query(
            "UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3 RETURNING *",
            [hashedToken, expiresAt, email]
        );

        if (updateResult.rowCount === 0) {
            return res.status(500).json({ message: "Failed to update reset token" });
        }

        // Send reset email
        await sendResetPassword(email, resetToken);

        console.log("Password reset email sent successfully.");
        res.json({ message: "Password reset email sent" });

    } catch (error) {
        console.error("Password reset error:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
} 