import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import pkg from 'pg';
import dotenv from 'dotenv';

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

// Database connection using Neon PostgreSQL URL from .env
const db = new Client({
    connectionString: process.env.DATABASE_URL, // Use DATABASE_URL from .env
    ssl: {
        rejectUnauthorized: false, // Necessary for SSL connections with Neon
    },
});

const corsOptions = {
    origin: 'https://reactfrontend-de123.netlify.app',  // Allow the frontend origin
    methods: ['GET', 'POST', 'PUT', 'DELETE'],  // Allow specific HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'],  // Allow Authorization header
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


app.get('/api/test-db-connection', async (req, res) => {
    try {
      // Attempt to connect to the database
      console.log('✅ Connected to PostgreSQL');
  
      // Test the connection with a simple query, like SELECT NOW() or SELECT version()
      const result = await db.query('SELECT NOW()');
      
      // Send success response with timestamp
      res.status(200).json({
        message: 'Database connection successful',
        timestamp: result.rows[0].now, // Current timestamp from the database
      });
    } catch (err) {
      console.error('Error connecting to PostgreSQL:', err);
      
      // Send error response if the connection fails
      res.status(500).json({
        message: 'Error connecting to database',
        error: err.message,
      });
    } finally {
      // Close the database connection
      await db.end();
    }
  });


// Add Cache-Control to prevent caching
app.get('/api/index', (req, res) => {
  res.set('Cache-Control', 'no-store'); // Disable caching to prevent 304 responses
  res.status(200).json({ message: 'Server is connected' });
});
// Token Generation
const generateToken = (user) => {
    if (!user) {
        throw new Error('User object is undefined');
    }

    // Validate and default missing fields (to avoid undefined errors)
    const role = user.role ? user.role.trim().toLowerCase() : 'user';  // Default role to 'user' if not available

    return jwt.sign(
        {
            id: user.id,
            email: user.email,
            name: user.name,
            role: role,
            balances: {
                BTC: user.BTC || 0,
                ETH: user.ETH || 0,
                ADA: user.ADA || 0,
                XRP: user.XRP || 0,
                DOGE: user.DOGE || 0,
                BNB: user.BNB || 0,
                SOL: user.SOL || 0,
                DOT: user.DOT || 0,
                total: user.total || 0,
            },
        },
        process.env.SECRET_KEY,
        { expiresIn: '1h' }
    );
};

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




// this is the fixed part of code for register, make the changes in others part of code to work properly as this one 
app.post('/auth/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({
            error: 'All fields are required',
            missing: ['name', 'email', 'password'].filter(f => !req.body[f])
        });
    }

    try {
        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);
        // Create the query to insert a new user
        const query = 'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id';
        
        // Use async/await with db.query() for better result handling
        const result = await db.query(query, [name, email, hashedPassword, 'user']);

        // Check if the result is valid and return a response
        if (result.rows.length > 0) {
            const userId = result.rows[0].id; // Get the inserted user id
            return res.status(201).json({
                message: 'Registration successful',
                userId: userId,
                nextStep: '/auth/login'
            });
        }

        // If for any reason the insertion didn't work as expected
        return res.status(500).json({
            error: 'Registration failed',
            code: 'DB_ERROR'
        });
    } catch (err) {
        console.error("❌ Registration error:", err);
        res.status(500).json({
            error: 'Internal server error',
            code: 'SERVER_ERROR'
        });
    }
});



// ✅ Debugging Log to Check All Registered Routes
app._router.stack.forEach((route) => {
    if (route.route && route.route.path) {
        console.log(`🛠 Registered Route: ${route.route.path}`);
    }
});

// ✅ Report Case Submission (Public)
app.post('/api/reports', (req, res) => {
    const { name, surname, email, description } = req.body;

    if (!name || !surname || !email || !description) {
        return res.status(400).json({ error: "All fields are required" });
    }

    const query = `
        INSERT INTO reports (name, surname, email, description, created_at)
        VALUES (?, ?, ?, ?, NOW())
    `;

    db.query(query, [name, surname, email, description], (err, result) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.status(201).json({ message: "Report submitted successfully!", reportId: result.insertId });
    });
});

// ✅ Contact Enquiry Submission (Public)
app.post('/api/contact', (req, res) => {
    const { enquiryType, fullName, email, phone, country, scamWebsite, lostMoney, message } = req.body;

    if (!enquiryType || !fullName || !email || !phone || !country || !message) {
        return res.status(400).json({ error: "All required fields must be filled" });
    }

    const query = `
        INSERT INTO enquiries (enquiryType, fullName, email, phone, country, scamWebsite, lostMoney, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `;

    db.query(query, [enquiryType, fullName, email, phone, country, scamWebsite || "", lostMoney || "", message], (err, result) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.status(201).json({ message: "Enquiry submitted successfully!", enquiryId: result.insertId });
    });
});


app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send({ error: 'All fields are required' });
    }

    const query = 'SELECT * FROM users WHERE email = $1';  // Use parameterized query for security
    db.query(query, [email], async (err, results) => {
        if (err) {
            return res.status(500).send({ error: 'Database error' });
        }

        if (results.rows.length === 0) {
            return res.status(404).send({ error: 'Invalid email or password' });
        }

        const user = results.rows[0];  // Get the user object from results

        // Verify the password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).send({ error: 'Invalid email or password' });
        }

        // Generate JWT token after password validation
        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role.trim().toLowerCase(),
                balances: {
                    BTC: user.BTC || 0,
                    ETH: user.ETH || 0,
                    ADA: user.ADA || 0,
                    XRP: user.XRP || 0,
                    DOGE: user.DOGE || 0,
                    BNB: user.BNB || 0,
                    SOL: user.SOL || 0,
                    DOT: user.DOT || 0,
                    total: user.total || 0,
                },
            },
            process.env.SECRET_KEY,  // Use the secret key from your environment
            { expiresIn: '1h' }  // Token expiration time (1 hour in this case)
        );

        // Send response with user data and token
        res.send({ message: 'Login successful', user, token });
    });
});




// ✅ Get All Users (Admin Only)
app.get('/api/users', authenticateJWT, checkRole('admin'), async (req, res) => {
    console.log("✅ Admin access granted to /api/users");

    // Log user information (helpful for debugging)
    console.log("✅ User info from JWT:", req.user);

    const query = `
        SELECT id, name, email, role, BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total
        FROM users;
    `;

    try {
        // Execute the query using the db client
        const { rows } = await db.query(query);  // Use db.query() instead of pool.query()

        // If no results found, return an appropriate response
        if (rows.length === 0) {
            return res.status(404).send({ error: 'No users found' });
        }

        // Send the rows of the result as the response
        res.status(200).send(rows);  // Access the rows property to get the actual data

    } catch (err) {
        // Log the error and send a 500 status code if there's a problem with the database query
        console.error("❌ Database error:", err);
        res.status(500).send({ error: 'Database error' });
    }
});


// ✅ Get Reports (Admin Only)
app.get('/api/reports', authenticateJWT, checkRole('admin'), async (req, res) => {
    console.log("✅ Admin access granted to /api/reports");

    const query = 'SELECT * FROM reports';

    try {
        const { rows } = await db.query(query); // Using async/await with db.query
        res.status(200).json({
            message: 'Successfully fetched all reports',
            data: rows, // Send results in 'data' field
        });
    } catch (err) {
        console.error("❌ Database error:", err);
        res.status(500).send({ error: 'Database error' });
    }
});


app.put('/api/users/:id', authenticateJWT, checkRole('admin'), async (req, res) => {
    const userId = req.params.id;
    const { BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total } = req.body;

    // Validate that required fields are present
    if (!BTC || !ETH || !ADA || !XRP || !DOGE || !BNB || !SOL || !DOT || !total) {
        return res.status(400).json({ error: "All balance fields are required" });
    }

    const query = `
        UPDATE users
        SET BTC = $1, ETH = $2, ADA = $3, XRP = $4, DOGE = $5, BNB = $6, SOL = $7, DOT = $8, total = $9
        WHERE id = $10;  
    `;

    try {
        const { rows } = await db.query(query, [BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total, userId]);
        
        if (rows.length === 0) {
            return res.status(404).send({ error: 'User not found' });
        }

        res.status(200).json({
            message: 'User updated successfully',
            updatedUser: rows[0] // Return the updated user object if necessary
        });
    } catch (err) {
        console.error("❌ Database error:", err);
        res.status(500).send({ error: 'Database error' });
    }
});


// ✅ Post Investment
app.post('/api/investments', async (req, res) => {
    const { first_name, last_name, phone_country_code, phone_number, email, investment_amount, details } = req.body;

    if (!first_name || !last_name || !phone_country_code || !phone_number || !email || !investment_amount) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    const query = `
        INSERT INTO investments (first_name, last_name, phone_country_code, phone_number, email, investment_amount, details)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *;  -- Optional: Return inserted row if you want
    `;

    try {
        const { rows } = await db.query(query, [first_name, last_name, phone_country_code, phone_number, email, investment_amount, details || ""]);

        res.status(201).json({
            message: "Investment submitted successfully!",
            investmentId: rows[0].id, // Return inserted investment ID (you can also return other details)
        });
    } catch (err) {
        console.error("❌ Database error:", err);
        res.status(500).json({ error: "Database error" });
    }
});




// ✅ Get All Investments (Admin Only)
app.get('/api/investments', authenticateJWT, checkRole('admin'), async (req, res) => {
    console.log("✅ Admin access granted to /api/investments");

    const query = 'SELECT * FROM investments';

    try {
        const { rows } = await db.query(query);

        res.status(200).json({
            message: 'Successfully fetched all investments',
            data: rows, // Send the data in a JSON object
        });
    } catch (err) {
        console.error('❌ Database error:', err);
        res.status(500).send({ error: 'Database error' });
    }
});


// ✅ Get All Contact Enquiries (Admin Only)
app.get('/api/contact', authenticateJWT, checkRole('admin'), (req, res) => {
    console.log("✅ Admin access granted to /api/contact");

    const query = 'SELECT * FROM enquiries';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send({ error: 'Database error' });
        }
        res.send(results);
    });
});

app.put('/api/trade', authenticateJWT, (req, res) => {
    const { userId, fromCurrency, toCurrency, amount, conversionRate } = req.body;

    if (!userId || !fromCurrency || !toCurrency || !amount || !conversionRate) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Convert amount based on the exchange rate
    const convertedAmount = amount * conversionRate;

    // Ensure user has enough balance to trade
    const checkBalanceQuery = `SELECT ${fromCurrency} FROM users WHERE id = ?`;
    db.query(checkBalanceQuery, [userId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const currentBalance = results[0][fromCurrency];
        if (currentBalance < amount) {
            return res.status(400).json({ error: `Insufficient ${fromCurrency} balance` });
        }

        // Update balances
        const tradeQuery = `
            UPDATE users
            SET ${fromCurrency} = ${fromCurrency} - ?, ${toCurrency} = ${toCurrency} + ?
            WHERE id = ?
        `;

        db.query(tradeQuery, [amount, convertedAmount, userId], (err, result) => {
            if (err) {
                console.error('Error updating balances:', err);
                return res.status(500).send({ error: 'Trade execution failed' });
            }
            res.json({ message: 'Trade successful', convertedAmount });
        });
    });
});

// ✅ Get User Balances by ID (Fix 404 Error)
app.get('/api/users/:id', authenticateJWT, (req, res) => {
    const userId = req.params.id;

    console.log("🔍 Fetching user balances for ID:", userId); // ✅ Debugging Log

    const query = `SELECT BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total FROM users WHERE id = ?`;
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('❌ Database error:', err);
            return res.status(500).send({ error: 'Database error' });
        }

        if (results.length === 0) {
            console.warn("⚠️ No user found for ID:", userId); // ✅ Debugging Log
            return res.status(404).json({ error: 'User not found' });
        }

        console.log("✅ User Balances:", results[0]); // ✅ Debugging Log
        res.json(results[0]); // Return user balances
    });
});

app.get('/api/userss1', (req, res) => {
    console.log("🔍 Fetching all users..."); // ✅ Debugging Log

    const query = `SELECT id, name, email, BTC, ETH, ADA, XRP, DOGE, BNB, SOL, DOT, total FROM users`;
    db.query(query, (err, results) => {
        if (err) {
            console.error('❌ Database error:', err);
            return res.status(500).send({ error: 'Database error' });
        }

        if (results.length === 0) {
            console.warn("⚠️ No users found in the database"); // ✅ Debugging Log
            return res.status(404).json({ error: 'No users found' });
        }

        console.log("✅ Fetched all users:", results); // ✅ Debugging Log
        res.json(results); // Return all users data
    });
});


// ✅ Update User's Total Balance in `users` Table
app.put('/api/update-total/:id', authenticateJWT, (req, res) => {
    const userId = req.params.id;
    const { total } = req.body;

    if (!total || isNaN(total)) {
        return res.status(400).send({ error: "Invalid total value" });
    }

    const query = `UPDATE users SET total = ? WHERE id = ?`;

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
