import pkg from 'pg';
const { Client } = pkg;

import dotenv from 'dotenv';

dotenv.config();
const port = process.env.PORT || 5000;
const db = new Client({
    connectionString: process.env.DATABASE_URL, // Use DATABASE_URL from .env
    ssl: {
        rejectUnauthorized: false, // Necessary for SSL connections with Neon
    },
});
connectDB();

module.exports = async (req, res) => {
    const id = 17; // Hardcoding the user ID to 17 for testing purposes

    // Your database query or logic to fetch user data by `id`
    try {
        // Example: query the database using the hardcoded ID (17)
        const userData = await db.query('SELECT * FROM users WHERE id = $1', [id]);

        if (userData.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        return res.status(200).json(userData.rows[0]);  // Return the user data as JSON
    } catch (err) {
        console.error('Error fetching user:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
};
