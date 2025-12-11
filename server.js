const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Simple in-memory storage for email submissions (replace with database later)
const submissions = [];

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/thank-you', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'thank-you.html'));
});

app.post('/api/submit', (req, res) => {
  const { email, name } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }
  
  // Store submission (in production, save to database)
  submissions.push({
    email,
    name: name || '',
    timestamp: new Date().toISOString()
  });
  
  console.log('New submission:', { email, name, total: submissions.length });
  
  res.json({ success: true });
});

// Admin route to view submissions (protect this in production!)
app.get('/admin/submissions', (req, res) => {
  res.json({
    total: submissions.length,
    submissions: submissions
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visit: http://localhost:${PORT}`);
});
