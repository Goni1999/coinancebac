import pkg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Client } = pkg;

// Create a single database client instance
const db = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
});

let isConnected = false;
let isConnecting = false;

// Connect to the PostgreSQL database
const connectDB = async () => {
    if (isConnected) {
        console.log('✅ Database already connected');
        return db;
    }
    
    if (isConnecting) {
        console.log('⏳ Database connection in progress...');
        // Wait for the connection to complete
        while (isConnecting) {
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        return db;
    }
    
    isConnecting = true;
    
    try {
        await db.connect();
        isConnected = true;
        isConnecting = false;
        console.log('✅ Connected to PostgreSQL');
        return db;
    } catch (err) {
        isConnecting = false;
        console.error('Error connecting to PostgreSQL:', err);
        setTimeout(() => {
            isConnected = false;
            connectDB();
        }, 5000);
        throw err;
    }
};

// Initialize connection
connectDB().catch(console.error);

// Handle process termination
process.on('SIGINT', async () => {
    if (isConnected) {
        await db.end();
        console.log('Database connection closed.');
    }
    process.exit(0);
});

process.on('SIGTERM', async () => {
    if (isConnected) {
        await db.end();
        console.log('Database connection closed.');
    }
    process.exit(0);
});

export { db, connectDB }; 