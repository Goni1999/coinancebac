import pkg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Client, Pool } = pkg;

// Use connection pooling for serverless environments
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
    // Serverless-optimized settings
    max: 1, // Maximum number of clients in the pool
    idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
    connectionTimeoutMillis: 10000, // Return an error if connection takes longer than 10 seconds
});

// Log database configuration (without sensitive info)
console.log('🔧 Database configuration:');
console.log('  - DATABASE_URL set:', !!process.env.DATABASE_URL);
console.log('  - SSL enabled: true');
console.log('  - Environment: Serverless (Pool-based)');

if (!process.env.DATABASE_URL) {
    console.error('❌ ERROR: DATABASE_URL environment variable not set!');
}

// Handle pool errors
pool.on('error', (err) => {
    console.error('❌ Unexpected error on idle client', err);
});

// For serverless, we export the pool and a query function
const query = async (text, params) => {
    const start = Date.now();
    try {
        const res = await pool.query(text, params);
        const duration = Date.now() - start;
        console.log('✅ Query executed', { duration, rows: res.rowCount });
        return res;
    } catch (err) {
        const duration = Date.now() - start;
        console.error('❌ Query error', { duration, error: err.message });
        throw err;
    }
};

// For backwards compatibility, create a db object that mimics the Client interface
const db = {
    query: query,
    end: () => pool.end(),
    // Add connect method for compatibility, but it's a no-op with pools
    connect: () => Promise.resolve(),
};

// Test connection on startup
const testConnection = async () => {
    try {
        await query('SELECT NOW() as current_time');
        console.log('✅ Database connection test successful');
    } catch (err) {
        console.error('❌ Database connection test failed:', err.message);
    }
};

// Test connection immediately
testConnection();

// Handle process termination
process.on('SIGINT', async () => {
    console.log('🔄 Closing database pool...');
    await pool.end();
    console.log('✅ Database pool closed');
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('🔄 Closing database pool...');
    await pool.end();
    console.log('✅ Database pool closed');
    process.exit(0);
});

export { db, query, pool }; 