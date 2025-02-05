// test.js
const express = require('express');
const app = express();
const port = 3000;

// Route to show the server is running
app.get('/', (req, res) => {
  res.send('Server running at http://localhost:3000');
});

// Serve the app locally
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
