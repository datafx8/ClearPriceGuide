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
const feedbackData = [];

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/thank-you', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'thank-you.html'));
});

app.post('/api/submit', (req, res) => {
  const { email, name } = req.body;


// Feedback endpoint for price comparison interest
app.post('/api/feedback', (req, res) => {
  const { interest, detailedFeedback, zipCode, timestamp } = req.body;
  
  if (!interest) {
    return res.status(400).json({ error: 'Interest level required' });
  }
  
  // Store feedback
  feedbackData.push({
    interest,
    detailedFeedback: detailedFeedback || '',
    zipCode: zipCode || null,
    timestamp: timestamp || new Date().toISOString()
  });
  
  console.log('New feedback:', { 
    interest, 
    hasDetails: !!detailedFeedback, 
    hasZip: !!zipCode,
    total: feedbackData.length 
  });
  
  res.json({ success: true });
});
  
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

// Admin route to view feedback (protect this in production!)
app.get('/admin/feedback', (req, res) => {
  const summary = {
    total: feedbackData.length,
    breakdown: {
      yes: feedbackData.filter(f => f.interest === 'yes').length,
      no: feedbackData.filter(f => f.interest === 'no').length
    },
    detailedFeedback: feedbackData.filter(f => f.detailedFeedback).length,
    withZipCode: feedbackData.filter(f => f.zipCode).length,
    topZipCodes: getTopZipCodes(feedbackData),
    allFeedback: feedbackData
  };
  
  res.json(summary);
});

// Helper function to get top zip codes
function getTopZipCodes(data) {
  const zipCounts = {};
  data.forEach(item => {
    if (item.zipCode) {
      zipCounts[item.zipCode] = (zipCounts[item.zipCode] || 0) + 1;
    }
  });
  
  return Object.entries(zipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([zip, count]) => ({ zipCode: zip, count }));
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visit: http://localhost:${PORT}`);
});
