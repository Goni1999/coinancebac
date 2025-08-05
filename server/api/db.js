import pkg from 'pg';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const { Client, Pool } = pkg;

// Enhanced environment variable validation
let DATABASE_URL = process.env.DATABASE_URL;
const NODE_ENV = process.env.NODE_ENV || 'development';
const VERCEL_ENV = process.env.VERCEL_ENV;

// Log comprehensive environment info
console.log('🔧 Database Environment Check:');
console.log('  - NODE_ENV:', NODE_ENV);
console.log('  - VERCEL_ENV:', VERCEL_ENV);
console.log('  - DATABASE_URL set:', !!DATABASE_URL);
console.log('  - Environment: Serverless (Pool-based)');

// Fallback for Vercel deployment - try alternative environment variable names
if (!DATABASE_URL) {
    console.warn('⚠️ DATABASE_URL not found, checking alternatives...');
    
    // Try common alternative names
    DATABASE_URL = process.env.POSTGRES_URL || 
                  process.env.POSTGRESQL_URL || 
                  process.env.DB_URL ||
                  process.env.NEON_DATABASE_URL;
    
    if (DATABASE_URL) {
        console.log('✅ Found database URL in alternative environment variable');
    } else {
        console.error('❌ CRITICAL ERROR: No database URL found in environment variables!');
        console.error('   Available environment variables:', Object.keys(process.env).filter(key => 
            key.includes('DATABASE') || key.includes('DB') || key.includes('POSTGRES') || key.includes('NEON')
        ));
        
        // For development, provide the fallback URL
        if (NODE_ENV === 'development') {
            console.warn('🔄 Using development fallback database URL...');
            DATABASE_URL = 'postgres://neondb_owner:npg_GUnkL7AYE5lw@ep-autumn-feather-a2hf171v-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require';
        } else {
            throw new Error('DATABASE_URL environment variable is required for production');
        }
    }
}

// Validate DATABASE_URL format
if (!DATABASE_URL.startsWith('postgres://') && !DATABASE_URL.startsWith('postgresql://')) {
    console.error('❌ INVALID DATABASE_URL format. Expected postgres:// or postgresql://');
    console.error('   Current value starts with:', DATABASE_URL.substring(0, 15) + '...');
    throw new Error('Invalid DATABASE_URL format');
}

console.log('✅ DATABASE_URL validation passed');
console.log('   Connection string starts with:', DATABASE_URL.substring(0, 15) + '...');

// Use connection pooling for serverless environments
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
    // Serverless-optimized settings
    max: 1, // Maximum number of clients in the pool
    idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
    connectionTimeoutMillis: 10000, // Return an error if connection takes longer than 10 seconds
});

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