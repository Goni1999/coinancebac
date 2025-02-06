import express from 'express';
import cors from 'cors';

const app = express();
const port = process.env.PORT || 5000;

// Enable CORS for requests from Netlify
const corsOptions = {
  origin: 'https://reactfrontend-de123.netlify.app', // Your Netlify frontend domain
  methods: ['GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
};

// Use CORS middleware
app.use(cors(corsOptions));

// Add Cache-Control to prevent caching
app.get('/api/status', (req, res) => {
  res.set('Cache-Control', 'no-store'); // Disable caching to prevent 304 responses
  res.status(200).json({ message: 'Server is connected' });
});

// Export the function as a serverless handler for Vercel
export default app;
