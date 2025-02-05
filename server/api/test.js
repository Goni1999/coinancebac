// api/test.js
module.exports = (req, res) => {
    // Simple response to confirm connection
    res.status(200).json({ message: 'Server is connected' });
  };
  