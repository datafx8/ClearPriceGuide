const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Tell Express to trust Render's load balancer
app.set('trust proxy', 1);

// Security: Helmet sets various HTTP headers for security
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: [
        "'self'", 
        "'unsafe-inline'", 
        "https://www.googletagmanager.com",
        "https://cdnjs.cloudflare.com"
      ],
      scriptSrc: [
        "'self'", 
        "'unsafe-inline'",
        "https://www.googletagmanager.com",
        "https://cdnjs.cloudflare.com"
      ],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: [
        "'self'", 
        "data:", 
        "https:", 
        "https://www.googletagmanager.com",
        "https://*.tile.openstreetmap.org"
      ],
      connectSrc: [
        "'self'", 
        "https://www.google-analytics.com",
        "https://nominatim.openstreetmap.org"
      ],
    },
  },
}));

// Security: CORS - only allow requests from your domain
// In development, this allows all origins. In production, set your domain.
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://pricedoctor.io', 'https://www.pricedoctor.io']
    : '*',
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true, limit: '10kb' })); // Limit payload size
app.use(express.json({ limit: '10kb' })); // Limit payload size

// Security: Rate limiting to prevent spam/DoS
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Stricter rate limit for submission endpoints
const submissionLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Max 10 submissions per hour per IP
  message: 'Too many submissions, please try again later.',
  skipSuccessfulRequests: false,
});

// Simple in-memory storage (replace with database in production)
const submissions = [];

// DB connection
const { Pool } = require('pg');

// Use the environment variable Render provides
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Required for Render connections
});

// Security: Simple authentication for admin endpoints
// In production, use proper authentication (JWT, OAuth, etc.)
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-this-in-production';

function requireAdminAuth(req, res, next) {
  const authKey = req.headers['x-admin-key'] || req.query.key;
  
  if (!authKey || authKey !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  next();
}

// Sanitize function to prevent XSS
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  
  return input
    .replace(/[<>]/g, '') // Remove < and > to prevent HTML injection
    .trim()
    .substring(0, 5000); // Limit length
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/thank-you', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'thank-you.html'));
});
app.get('/resources', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'resources.html'));
});
app.get('/about', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'about.html'));
});
app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'terms.html'));
});
app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'privacy.html'));
});
app.get('/cookie', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'cookie.html'));
});


// Email submission endpoint with validation
app.post('/api/submit',
  submissionLimiter,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('name').optional().isLength({ max: 100 }).trim().escape(),
  ],
  (req, res) => {
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, name } = req.body;

    // Additional sanitization
    const sanitizedName = sanitizeInput(name || '');

    // Store submission
    submissions.push({
      email,
      name: sanitizedName,
      timestamp: new Date().toISOString(),
      ip: req.ip // Store IP for abuse tracking
    });

    console.log('New submission:', { email, name: sanitizedName, total: submissions.length });

    res.json({ success: true });
  }
);

// Feedback endpoint with validation
// 1. Added 'async' to the function signature
app.post('/api/feedback',
  submissionLimiter,
  [
    body('interest').isIn(['yes', 'no']).withMessage('Interest must be yes or no'),
    body('detailedFeedback').optional().isLength({ max: 2000 }).trim(),
    body('zipCode').optional().matches(/^\d{5}$/).withMessage('Zip code must be 5 digits'),
  ],
  async (req, res) => { // <-- Added async here
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { interest, detailedFeedback, zipCode } = req.body;
    const userIp = req.ip; // <--- This extracts the IP address

    // Additional sanitization
    const sanitizedFeedback = sanitizeInput(detailedFeedback || '');

    try {
      // 2. Replace .push with SQL Insert
      const queryText = `
        INSERT INTO feedback (answer, detailed_feedback, zip_code, timestamp, ip)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
      `;
      
      const values = [
        interest, 
        sanitizedFeedback, 
        zipCode || null, 
        new Date().toISOString(), 
        userIp // <--- This ensures the IP actually goes to the DB
      ];

      const result = await pool.query(queryText, values);

      console.log('New feedback saved to DB. ID:', result.rows[0].id, {
        interest,
        hasDetails: !!sanitizedFeedback,
        hasZip: !!zipCode
      });

      res.json({ success: true });

    } catch (err) {
      console.error('Database Error:', err);
      // Still send a success to the user so the UI doesn't break, 
      // or send a 500 if you want them to try again.
      res.status(500).json({ error: 'Internal server error saving feedback' });
    }
  }
);

// Contact form endpoint with validation
app.post('/api/contact',
  submissionLimiter,
  [
    body('contactType').isIn(['feedback', 'advertisement inquiry', 'other']).withMessage('Invalid contact type'),
    body('name').notEmpty().isLength({ max: 100 }).trim().escape().withMessage('Name is required'),
    body('phone').notEmpty().matches(/^[\d\s\-\(\)\+\.]+$/).isLength({ max: 20 }).withMessage('Valid phone number required'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('organizationName').optional().isLength({ max: 200 }).trim().escape(),
    body('message').notEmpty().isLength({ max: 5000 }).trim().withMessage('Message is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { contactType, name, phone, email, organizationName, message } = req.body;
    const userIp = req.ip;

    // Additional sanitization
    const sanitizedName = sanitizeInput(name);
    const sanitizedPhone = sanitizeInput(phone);
    const sanitizedOrg = sanitizeInput(organizationName || '');
    const sanitizedMessage = sanitizeInput(message);

    try {
      const queryText = `
        INSERT INTO contact_submissions (contact_type, name, phone, email, organization_name, message, timestamp, ip)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
      `;
      
      const values = [
        contactType,
        sanitizedName,
        sanitizedPhone,
        email,
        sanitizedOrg,
        sanitizedMessage,
        new Date().toISOString(),
        userIp
      ];

      const result = await pool.query(queryText, values);

      console.log('New contact submission saved to DB. ID:', result.rows[0].id, {
        contactType,
        name: sanitizedName,
        email
      });

      res.json({ success: true });

    } catch (err) {
      console.error('Database Error:', err);
      res.status(500).json({ error: 'Internal server error saving contact form' });
    }
  }
);

// Protected admin routes
app.get('/admin/submissions', requireAdminAuth, (req, res) => {
  res.json({
    total: submissions.length,
    submissions: submissions
  });
});

app.get('/admin/feedback', requireAdminAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM feedback ORDER BY timestamp DESC');
    const rows = result.rows;

    res.json({
      total: rows.length,
      breakdown: {
        yes: rows.filter(f => f.interest === 'yes').length,
        no: rows.filter(f => f.interest === 'no').length
      },
      allFeedback: rows
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch' });
  }
});

// Helper function
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


// Map page route
app.get('/map', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'map.html'));
});


// Entity search endpoint - connects to your PostgreSQL database
app.post('/api/entities',
  submissionLimiter,
  [
    body('lat').isFloat({ min: -90, max: 90 }),
    body('lng').isFloat({ min: -180, max: 180 }),
    body('radius').isInt({ min: 1, max: 200 }),
    body('procedureType').optional().isString().trim(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { lat, lng, radius, procedureType } = req.body;

    try {
      // Build WHERE clause based on whether procedure is selected
      let whereClause = 'WHERE e.price > 0';
      const queryParams = [lat, lng, radius];
      
      if (procedureType) {
        whereClause += ' AND e.procedure_type = $4';
        queryParams.push(procedureType);
      }
      
      // PostgreSQL query using Haversine formula
      const query = `
        SELECT 
          e.id,
          e.name,
          e.address,
          e.latitude as lat,
          e.longitude as lng,
          e.phone,
          e.rating,
          e.price,
          e.price_self,      
          e.pricedate,       
          e.cptcode,         
          e.price_selfpercent,
          e.source,          
          e.sourceurl,       
          e.sourcefile,      
          e.sourceline,      
          e.procedure_type,
          e.parent_entity_id,
          p.name as parent_name,
          (
            3959 * acos(
              cos(radians($1)) * cos(radians(e.latitude)) * 
              cos(radians(e.longitude) - radians($2)) + 
              sin(radians($1)) * sin(radians(e.latitude))
            )
          ) AS distance
        FROM entities e
        LEFT JOIN entities p ON e.parent_entity_id = p.id
        ${whereClause}
          AND (
            3959 * acos(
              cos(radians($1)) * cos(radians(e.latitude)) * 
              cos(radians(e.longitude) - radians($2)) + 
              sin(radians($1)) * sin(radians(e.latitude))
            )
          ) <= $3
        ORDER BY distance
        LIMIT 50
      `;
      
      const result = await pool.query(query, queryParams);
      
      res.json({ entities: result.rows });
      
    } catch (error) {
      console.error('Database query error:', error);
      res.status(500).json({ error: 'Failed to fetch entities' });
    }
  }
);

// Get unique procedures endpoint
app.get('/api/procedures', async (req, res) => {
  try {
    const query = `
      SELECT DISTINCT procedure_type
      FROM entities
      WHERE procedure_type IS NOT NULL
        AND procedure_type != ''
        AND procedure_type != 'Health System'
      ORDER BY procedure_type
    `;
    
    const result = await pool.query(query);
    res.json({ procedures: result.rows.map(row => row.procedure_type) });
    
  } catch (error) {
    console.error('Error fetching procedures:', error);
    res.status(500).json({ error: 'Failed to fetch procedures' });
  }
});

// Security: Handle 404s
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Security: Error handler (don't leak stack traces in production)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message 
  });
});


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visit: http://localhost:${PORT}`);
  console.log(`Admin key: ${ADMIN_KEY}`);
});