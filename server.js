// 1. FIRST: All imports
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const OAuthClient = require('intuit-oauth');
const crypto = require('crypto');
const fetch = require('node-fetch');
require('dotenv').config();

// 2. SECOND: Basic setup
const app = express();
const PORT = process.env.PORT || 3000;

// 3. THIRD: Database initialization
const dbPath = process.env.DATABASE_PATH || './data/customers.db';
const db = new sqlite3.Database(dbPath);

// 4. FOURTH: Constants (after dotenv loads)
const REQUIRED_SCOPES = [
  'profile',
  'email',
  'https://www.googleapis.com/auth/spreadsheets.readonly',
  'https://www.googleapis.com/auth/spreadsheets',
  'https://www.googleapis.com/auth/contacts.other.readonly',
  'https://www.googleapis.com/auth/contacts.readonly',
  'https://www.googleapis.com/auth/contacts',
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/gmail.compose',
  'https://www.googleapis.com/auth/gmail.labels',
  'https://www.googleapis.com/auth/calendar',
  'https://www.googleapis.com/auth/drive'
];
const QB_SCOPES = [OAuthClient.scopes.Accounting];
const QB_ENVIRONMENT = process.env.NODE_ENV === 'production' ? 'production' : 'sandbox';

// 5. FIFTH: OAuth clients (after environment variables are loaded)
const qbOAuthClient = new OAuthClient({
  clientId: process.env.QB_CLIENT_ID,
  clientSecret: process.env.QB_CLIENT_SECRET,
  environment: QB_ENVIRONMENT,
  redirectUri: 'https://auth.robosouthla.com/auth/quickbooks/callback'
});

// Create tables if they don't exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    name TEXT,
    picture TEXT,
    google_access_token TEXT,
    google_refresh_token TEXT,
    scopes TEXT,
    token_expiry DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Add QuickBooks columns to existing customers table
db.serialize(() => {
  db.run(`ALTER TABLE customers ADD COLUMN qb_access_token TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column')) console.log('QB access token column exists');
  });

  db.run(`ALTER TABLE customers ADD COLUMN qb_refresh_token TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column')) console.log('QB refresh token column exists');
  });

  db.run(`ALTER TABLE customers ADD COLUMN qb_company_id TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column')) console.log('QB company ID column exists');
  });

  db.run(`ALTER TABLE customers ADD COLUMN qb_token_expiry DATETIME`, (err) => {
    if (err && !err.message.includes('duplicate column')) console.log('QB token expiry column exists');
  });

  db.run(`ALTER TABLE customers ADD COLUMN qb_base_url TEXT`, (err) => {
    if (err && !err.message.includes('duplicate column')) console.log('QB base URL column exists');
  });
});

// Middleware to force HTTPS detection
app.use((req, res, next) => {
  if (req.get('host') === 'auth.robosouthla.com') {
    req.headers['x-forwarded-proto'] = 'https';
  }
  next();
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

// Authentication middleware function
function requireAuth(req, res, next) {
  console.log('Session check:', {
    authenticated: req.session.authenticated,
    sessionID: req.sessionID,
    hasSession: !!req.session
  });
  if (req.session.authenticated) {
    next();
  } else {
    console.log('Session not authenticated, redirecting to login');
    res.redirect('/login');
  }
}

// Passport configuration with proper scopes
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "https://auth.robosouthla.com/auth/google/callback",
  scope: REQUIRED_SCOPES,
  accessType: 'offline',
  prompt: 'consent'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const customerId = uuidv4();
    const customerData = {
      id: customerId,
      email: profile.emails[0].value,
      name: profile.displayName,
      picture: profile.photos?.[0]?.value || null,
      accessToken,
      refreshToken,
      scopes: REQUIRED_SCOPES.join(' '),
      tokenExpiry: new Date(Date.now() + (3600 * 1000))
    };

    await storeCustomer(customerData);
    console.log(`New customer with Sheets access: ${customerData.email} (${customerId})`);

    return done(null, customerData);
  } catch (error) {
    console.error('Auth error:', error);
    return done(error, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const customer = await getCustomerById(id);
    done(null, customer);
  } catch (error) {
    done(error, null);
  }
});

// Database functions
function storeCustomer(customerData) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO customers 
      (id, email, name, picture, google_access_token, google_refresh_token, scopes, token_expiry, 
       qb_access_token, qb_refresh_token, qb_company_id, qb_token_expiry, qb_base_url, updated_at) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `);

    stmt.run([
      customerData.id,
      customerData.email,
      customerData.name,
      customerData.picture,
      customerData.accessToken,
      customerData.refreshToken,
      customerData.scopes,
      customerData.tokenExpiry,
      customerData.qbAccessToken || null,
      customerData.qbRefreshToken || null,
      customerData.qbCompanyId || null,
      customerData.qbTokenExpiry || null,
      customerData.qbBaseUrl || null
    ], function (err) {
      if (err) reject(err);
      else resolve(this.lastID);
    });

    stmt.finalize();
  });
}

function getCustomerById(id) {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM customers WHERE id = ?', [id], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function getAllCustomers() {
  return new Promise((resolve, reject) => {
    db.all('SELECT * FROM customers ORDER BY created_at DESC', (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

async function validateToken(accessToken) {
  try {
    console.log('Validating token...', accessToken.substring(0, 20) + '...');
    const response = await fetch(`https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${accessToken}`);
    console.log('Token validation response status:', response.status);

    if (response.ok) {
      const data = await response.json();
      console.log('Token validation result:', {
        valid: true,
        expires_in: data.expires_in,
        scopes: data.scope ? data.scope.split(' ').length : 0
      });
      return {
        valid: true,
        expires_in: data.expires_in,
        scopes: data.scope ? data.scope.split(' ') : []
      };
    } else {
      const errorText = await response.text();
      console.log('Token validation failed:', response.status, errorText);
      return { valid: false };
    }
  } catch (error) {
    console.log('Token validation error:', error.message);
    return { valid: false, error: error.message };
  }
}

async function updateCustomerQBTokens(customerId, qbData) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(`
      UPDATE customers 
      SET qb_access_token = ?, qb_refresh_token = ?, qb_company_id = ?, 
          qb_token_expiry = ?, qb_base_url = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `);

    stmt.run([
      qbData.qbAccessToken,
      qbData.qbRefreshToken,
      qbData.qbCompanyId,
      qbData.qbTokenExpiry,
      qbData.qbBaseUrl,
      customerId
    ], function (err) {
      if (err) reject(err);
      else resolve(this.changes);
    });

    stmt.finalize();
  });
}

async function validateQBToken(accessToken, companyId) {
  // For now, just check if we have the required values
  // The actual QB API calls in workflows will handle any token issues
  const hasValidInputs = !!(accessToken && companyId);

  console.log('QB Token validation:', {
    hasAccessToken: !!accessToken,
    hasCompanyId: !!companyId,
    companyId: companyId
  });

  return {
    valid: hasValidInputs,
    status: hasValidInputs ? 200 : 401
  };
}

// Login routes for Google reviewers
app.get('/login', (req, res) => {
  const error = req.query.error ? '<p style="color: red;">Invalid credentials</p>' : '';
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>OAuth Demo - Reviewer Login</title>
      <style>
        body { font-family: Arial; max-width: 400px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { background: #4285f4; color: white; padding: 12px; border: none; border-radius: 4px; width: 100%; font-size: 16px; cursor: pointer; }
        button:hover { background: #3367d6; }
        h2 { color: #333; text-align: center; }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>Google Reviewer Access</h2>
        <p>Please use the credentials provided by the development team:</p>
        ${error}
        <form method="POST" action="/login">
          <input type="text" name="username" placeholder="Username" required>
          <input type="password" name="password" placeholder="Password" required>
          <button type="submit">Login</button>
        </form>
      </div>
    </body>
    </html>
  `);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt for:', username);

  if (username === 'reviewer@robosouthla.com' && password === 'GoogleReview2024!') {
    req.session.authenticated = true;
    console.log('Login successful, session set:', req.sessionID);
    res.redirect('/');
  } else {
    console.log('Login failed for:', username);
    res.redirect('/login?error=1');
  }
});

// Routes
// Replace the existing home route (app.get('/')) in your server.js with this updated version:
app.get('/', requireAuth, (req, res) => {
  res.send(`
    <html>
    <head>
      <title>AI Workflow Portal</title>
      <style>
        body { 
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
          text-align: center; 
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
          margin: 0;
          padding: 50px 20px;
          min-height: 100vh;
          box-sizing: border-box;
        }
        .container { 
          background: white; 
          padding: 40px; 
          border-radius: 15px; 
          max-width: 800px; 
          margin: 0 auto; 
          box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }
        .logo { 
          margin-bottom: 20px; 
          display: flex;
          justify-content: center;
          align-items: center;
        }
        .logo img {
          transition: transform 0.3s ease;
          width: 400px;
          height: auto;
          max-height: 128px;
          object-fit: contain;
        }
        .logo img:hover {
          transform: scale(1.05);
        }
        
        /* Modern Rounded Button Styles */
        .btn-modern {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 16px 24px;
          border: none;
          border-radius: 12px;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
          text-decoration: none;
          min-width: 200px;
          justify-content: flex-start;
          width: 100%;
          box-sizing: border-box;
        }

        .btn-google-modern {
          background: white;
          color: #757575;
          border: 2px solid #dadce0;
        }

        .btn-google-modern:hover {
          box-shadow: 0 8px 25px rgba(0,0,0,0.15);
          transform: translateY(-2px);
        }

        .btn-qb-modern {
          background: #0077c5;
          color: white;
        }

        .btn-qb-modern:hover {
          background: #005a94;
          transform: translateY(-2px);
          box-shadow: 0 8px 25px rgba(0,119,197,0.3);
        }

        /* Logo styles */
        .logo-icon {
          width: 20px;
          height: 20px;
          flex-shrink: 0;
          margin-right: 8px;
        }

        .logo-google {
          background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTIyLjU2IDEyLjI1YzAtLjc4LS4wNy0xLjUzLS4yLTIuMjVIMTJ2NC4yNmg1LjkyYy0uMjYgMS4zNy0xLjA0IDIuNTMtMi4yMSAzLjMxdjIuNzdoMy41N2MyLjA4LTEuOTIgMy4yOC00Ljc0IDMuMjgtOC4wOXoiIGZpbGw9IiM0Mjg1RjQiLz4KPHBhdGggZD0iTTEyIDIzYzIuOTcgMCA1LjQ2LS45OCA3LjI4LTIuNjZsLTMuNTctMi43N2MtLjk4LjY2LTIuMjMgMS4wNi0zLjcxIDEuMDYtMi44NiAwLTUuMjktMS45My02LjE2LTQuNTNIMi4xOHYyLjg0QzMuOTkgMjAuNTMgNy43IDIzIDEyIDIzeiIgZmlsbD0iIzM0QTg1MyIvPgo8cGF0aCBkPSJNNS44NCAxNC4wOWMtLjIyLS42Ni0uMzUtMS4zNi0uMzUtMi4wOXMuMTMtMS40My4zNS0yLjA5VjcuMDdIMi4xOEMxLjQzIDguNTUgMSAxMC4yMiAxIDEycy40MyAzLjQ1IDEuMTggNC45M2w0LjY2LTIuODR6IiBmaWxsPSIjRkJCQzA1Ii8+CjxwYXRoIGQ9Ik0xMiA1LjM4YzEuNjIgMCAzLjA2LjU2IDQuMjEgMS42NGwzLjE1LTMuMTVDMTcuNDUgMi4wOSAxNC45NyAxIDEyIDEgNy43IDEgMy45OSAzLjQ3IDIuMTggNy4wN2w0LjY2IDIuODRjLjg3LTIuNiAzLjMtNC41MyA2LjE2LTQuNTN6IiBmaWxsPSIjRUE0MzM1Ii8+Cjwvc3ZnPgo=') no-repeat center;
          background-size: contain;
        }

        .logo-quickbooks {
          background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiByeD0iNCIgZmlsbD0iIzAwNzdDNSIvPgo8cGF0aCBkPSJNNyA2SDE3QzE4LjEwNDYgNiAxOSA2Ljg5NTQzIDE5IDhWMTZDMTkgMTcuMTA0NiAxOC4xMDQ2IDE4IDE3IDE4SDdDNS44OTU0MyAxOCA1IDE3LjEwNDYgNSAxNlY4QzUgNi44OTU0MyA1Ljg5NTQzIDYgNyA2WiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTggMTBIMTBWMTRIOFYxMFoiIGZpbGw9IiMwMDc3QzUiLz4KPHA+dGggZD0iTTEyIDhIMTRWMTZIMTJWOFoiIGZpbGw9IiMwMDc3QzUiLz4KPHA+dGggZD0iTTE2IDEyVjE0SDE2VjEyWiIgZmlsbD0iIzAwNzdDNSIvPgo8Y2lyY2xlIGN4PSIxNiIgY3k9IjEwIiByPSIxIiBmaWxsPSIjMDA3N0M1Ii8+Cjwvc3ZnPgo=') no-repeat center;
          background-size: contain;
        }
        
        .auth-options {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 20px;
          margin: 30px 0;
          align-items: stretch;
        }
        .auth-card {
          background: #f8f9fa;
          padding: 25px;
          border-radius: 12px;
          border: 2px solid #e9ecef;
          transition: all 0.3s ease;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          min-height: 320px;
        }
        .auth-card:hover {
          border-color: #007bff;
          transform: translateY(-2px);
        }
        .auth-card.google { border-left: 4px solid #4285f4; }
        .auth-card.quickbooks { border-left: 4px solid #0077C5; }
        .auth-card h3 { 
          margin-top: 0; 
          color: #333;
          margin-bottom: 20px;
        }
        .feature-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 15px;
          margin: 20px 0;
          flex-grow: 1;
        }
        .feature-item { 
          display: flex; 
          align-items: center; 
          padding: 8px;
          font-size: 14px;
        }
        .feature-icon { margin-right: 10px; font-size: 16px; }
        .or-divider {
          display: flex;
          align-items: center;
          margin: 30px 0;
        }
        .or-divider::before,
        .or-divider::after {
          content: '';
          flex: 1;
          height: 1px;
          background: #ddd;
        }
        .or-divider span {
          padding: 0 20px;
          color: #666;
          font-weight: 500;
        }
        @media (max-width: 768px) {
          .auth-options { 
            grid-template-columns: 1fr; 
            gap: 15px;
          }
          .container { 
            padding: 30px 20px; 
            max-width: 95%;
          }
          .auth-card {
            min-height: auto;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="logo">
          <img src="https://www.robosouthla.com/wp-content/uploads/2025/05/cropped-logo.png" alt="AI Workflow Portal">
        </div>
        <h1>AI Workflow Portal</h1>
        <p style="font-size: 18px; color: #666; margin-bottom: 30px;">
          Connect your business tools to unlock powerful AI workflows
        </p>
        
        <div class="auth-options">
          <div class="auth-card google">
            <h3>🔗 Google Workspace</h3>
            <div class="feature-grid">
              <div class="feature-item">
                <span class="feature-icon">📊</span>
                <span>Google Sheets</span>
              </div>
              <div class="feature-item">
                <span class="feature-icon">📧</span>
                <span>Gmail</span>
              </div>
              <div class="feature-item">
                <span class="feature-icon">📅</span>
                <span>Calendar</span>
              </div>
              <div class="feature-item">
                <span class="feature-icon">👥</span>
                <span>Contacts</span>
              </div>
              <div class="feature-item">
                <span class="feature-icon">💾</span>
                <span>Drive</span>
              </div>
            </div>
            <a href="/auth/google" class="btn-modern btn-google-modern">
              <div class="logo-icon logo-google"></div>
              <span>Continue with Google</span>
            </a>
          </div>
          
          <div class="auth-card quickbooks">
            <h3>📊 QuickBooks Online</h3>
            <div class="feature-grid">
              <div class="feature-item">
                <span class="feature-icon">🧾</span>
                <span>Invoices</span>
              </div>
              <div class="feature-item">
                <span class="feature-icon">👥</span>
                <span>Customers</span>
              </div>
              <div class="feature-item">
                <span class="feature-icon">📦</span>
                <span>Items</span>
              </div>
              <div class="feature-item">
                <span class="feature-icon">💰</span>
                <span>Reports</span>
              </div>
              <div class="feature-item">
                <span class="feature-icon">📈</span>
                <span>Sales Data</span>
              </div>
            </div>
            <a href="/auth/quickbooks/standalone" class="btn-modern btn-qb-modern">
              <div class="logo-icon logo-quickbooks"></div>
              <span>Connect QuickBooks</span>
            </a>
          </div>
        </div>
        
        <div class="or-divider">
          <span>Choose one or both integrations</span>
        </div>
        
        <p style="font-size: 14px; color: #888; margin-top: 20px;">
          Each integration is independent - you can connect one or both based on your workflow needs
        </p>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
          <a href="/debug" style="color: #666; font-size: 12px; margin: 0 10px;">Debug Info</a> | 
          <a href="/admin" style="color: #666; font-size: 12px; margin: 0 10px;">Admin Panel</a> | 
          <a href="/health" style="color: #666; font-size: 12px; margin: 0 10px;">Health Check</a>
        </div>
      </div>
    </body>
    </html>
  `);
});

app.get('/auth/google',
  passport.authenticate('google', {
    scope: REQUIRED_SCOPES,
    accessType: 'offline',
    prompt: 'consent'
  })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth-result?google_error=auth_failed' }),
  (req, res) => {
    res.redirect(`/auth-result?google_success=1&customer_id=${req.user.id}`);
  }
);

app.get('/dashboard', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }

  const customer = await getCustomerById(req.user.id);
  const hasQBAuth = !!(customer.qb_access_token && customer.qb_company_id);

  const urlParams = new URL(req.url, `http://${req.get('host')}`);
  const qbSuccess = urlParams.searchParams.get('qb_success');
  const qbError = urlParams.searchParams.get('qb_error');

  let qbStatusMessage = '';
  if (qbSuccess) {
    qbStatusMessage = '<div style="background: #d4edda; color: #155724; padding: 10px; margin: 10px 0; border-radius: 5px;">✅ QuickBooks connected successfully!</div>';
  } else if (qbError) {
    const errorMessages = {
      'auth_failed': 'QuickBooks authorization failed. Please try again.',
      'session_lost': 'Session expired. Please try connecting QuickBooks again.',
      'token_save_failed': 'Failed to save QuickBooks tokens. Please try again.'
    };
    qbStatusMessage = `<div style="background: #f8d7da; color: #721c24; padding: 10px; margin: 10px 0; border-radius: 5px;">❌ ${errorMessages[qbError] || 'Unknown error occurred'}</div>`;
  }

  res.send(`
    <html>
    <head>
      <title>Dashboard</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .integration-card { 
          background: #f8f9fa; 
          border-left: 4px solid #007bff; 
          padding: 20px; 
          margin: 20px 0; 
          border-radius: 8px; 
        }
        .qb-card { border-left-color: #0077C5; }
        .google-card { border-left-color: #4285f4; }
        .connected { border-left-color: #28a745; background: #e8f5e8; }
        .btn { 
          padding: 12px 24px; 
          margin: 5px; 
          border: none; 
          border-radius: 6px; 
          cursor: pointer; 
          text-decoration: none; 
          display: inline-block; 
          font-weight: 500;
        }
        .btn-primary { background: #007bff; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-qb { background: #0077C5; color: white; }
        .btn:hover { opacity: 0.9; }
        .customer-id { 
          background: #f0f0f0; 
          padding: 8px 12px; 
          border-radius: 4px; 
          font-family: monospace; 
          font-size: 14px;
        }
        .status-badge {
          padding: 4px 12px;
          border-radius: 20px;
          font-size: 12px;
          font-weight: bold;
          text-transform: uppercase;
        }
        .status-connected { background: #d4edda; color: #155724; }
        .status-disconnected { background: #f8d7da; color: #721c24; }
        h3 { margin-top: 0; }
        .google-disconnect-btn {
          background: #fff;
          border: 1px solid #dadce0;
          border-radius: 4px;
          color: #3c4043;
          cursor: pointer;
          font-family: arial,sans-serif;
          font-size: 14px;
          height: 40px;
          letter-spacing: 0.25px;
          outline: none;
          overflow: hidden;
          padding: 0 12px;
          position: relative;
          text-align: center;
          transition: background-color .218s, border-color .218s, box-shadow .218s;
          vertical-align: middle;
          white-space: nowrap;
          text-decoration: none;
          display: inline-flex;
          align-items: center;
          justify-content: center;
        }

        .google-disconnect-btn:hover {
          box-shadow: 0 1px 3px rgba(0,0,0,.1);
          background-color: #f8f9fa;
        }

        .google-disconnect-btn:active {
          background-color: #f1f3f4;
          box-shadow: 0 1px 2px rgba(0,0,0,.1);
        }  
       </style>
    </head>
    <body>
      <div class="container">
        <h1>Welcome, ${req.user.name}! 👋</h1>
        <p><strong>Email:</strong> ${req.user.email}</p>
        <p><strong>Customer ID:</strong> <span class="customer-id">${req.user.id}</span>
          <button onclick="copyToClipboard('${req.user.id}')" class="btn btn-secondary" style="margin-left: 10px; padding: 6px 12px; font-size: 12px;">Copy</button>
        </p>
        
        ${qbStatusMessage}
        
        <div class="integration-card google-card connected">
          <h3>🔗 Google Workspace Integration 
            <span class="status-badge status-connected">Connected</span>
          </h3>
          <p>✅ Full access to Google Sheets, Gmail, Calendar, Contacts, and Drive</p>
          <p><strong>Scopes:</strong> Comprehensive AI workflow permissions</p>

          <div style="margin-top: 15px;">
            <form method="POST" action="/auth/google/disconnect" style="display: inline;">
              <button type="submit" class="google-disconnect-btn" onclick="return confirm('Are you sure you want to disconnect from Google?')">
                Disconnect Google
              </button>
            </form>
          </div>
        </div>

        <div class="integration-card qb-card ${hasQBAuth ? 'connected' : ''}">
          <h3>📊 QuickBooks Integration 
            <span class="status-badge ${hasQBAuth ? 'status-connected' : 'status-disconnected'}">
              ${hasQBAuth ? 'Connected' : 'Not Connected'}
            </span>
          </h3>
          
          ${hasQBAuth ? `
            <p>✅ Connected to QuickBooks Company</p>
            <p><strong>Company ID:</strong> <code style="background: #f0f0f0; padding: 4px 8px; border-radius: 4px;">${customer.qb_company_id}</code></p>
            <p><strong>Environment:</strong> <code style="background: #f0f0f0; padding: 4px 8px; border-radius: 4px;">${QB_ENVIRONMENT}</code></p>
            <button onclick="disconnectQuickBooks()" class="btn btn-danger">Disconnect QuickBooks</button>
          ` : `
            <p>Connect your QuickBooks account to enable AI workflows with your accounting data</p>
            <p><strong>Permissions:</strong> Read/Write access to QuickBooks accounting data</p>
            <a href="/auth/quickbooks" class="btn btn-qb">Connect QuickBooks</a>
          `}
        </div>
        
        <div class="integration-card">
          <h3>🔧 N8N Workflow Integration</h3>
          <p>Use your Customer ID in n8n workflows to access both Google and QuickBooks APIs:</p>
          <div style="background: white; padding: 15px; border-radius: 6px; margin: 10px 0;">
            <strong>Customer ID:</strong> <span class="customer-id">${req.user.id}</span>
            <button onclick="copyToClipboard('${req.user.id}')" class="btn btn-primary" style="margin-left: 10px;">Copy for N8N</button>
          </div>
          
          <h4>API Endpoints:</h4>
          <ul style="font-family: monospace; font-size: 13px; background: #f8f9fa; padding: 15px; border-radius: 6px;">
            <li><strong>Google:</strong> GET /api/customer/${req.user.id}</li>
            <li><strong>QuickBooks Status:</strong> GET /api/customer/${req.user.id}/quickbooks</li>
            <li><strong>QuickBooks Tokens:</strong> GET /api/customer/${req.user.id}/quickbooks/tokens</li>
          </ul>
        </div>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6;">
          <a href="/admin" class="btn btn-secondary">Admin Panel</a>
          <a href="/logout" class="btn btn-danger">Logout</a>
        </div>
      </div>
      
      <script>
        function copyToClipboard(text) {
          navigator.clipboard.writeText(text).then(() => {
            alert('Customer ID copied to clipboard!');
          }).catch(err => {
            console.error('Failed to copy:', err);
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            alert('Customer ID copied to clipboard!');
          });
        }
        
        async function disconnectQuickBooks() {
          if (!confirm('Are you sure you want to disconnect QuickBooks? This will remove access to your accounting data.')) {
            return;
          }
          
          try {
            const response = await fetch('/auth/quickbooks/disconnect', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              }
            });
            
            if (response.ok) {
              alert('QuickBooks disconnected successfully!');
              location.reload();
            } else {
              const error = await response.json();
              alert('Failed to disconnect QuickBooks: ' + error.error);
            }
          } catch (error) {
            alert('Error disconnecting QuickBooks: ' + error.message);
          }
        }
      </script>
    </body>
    </html>
  `);
});

// NEW: Auth result page for standalone flows
app.get('/auth-result', async (req, res) => {
  const urlParams = new URL(req.url, `http://${req.get('host')}`);
  const qbSuccess = urlParams.searchParams.get('qb_success');
  const qbError = urlParams.searchParams.get('qb_error');
  const googleSuccess = urlParams.searchParams.get('google_success');
  const customerId = urlParams.searchParams.get('customer_id');

  let customer = null;
  if (customerId) {
    try {
      customer = await getCustomerById(customerId);
    } catch (error) {
      console.error('Error fetching customer:', error);
    }
  }

  let statusMessage = '';
  let nextSteps = '';

  if (qbSuccess && customer) {
    statusMessage = `
      <div style="background: #d4edda; color: #155724; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #28a745;">
        <h3 style="margin-top: 0;">✅ QuickBooks Connected Successfully!</h3>
        <p>Company ID: <code>${customer.qb_company_id}</code></p>
        <p>Environment: <code>${QB_ENVIRONMENT}</code></p>
      </div>
    `;

    const hasGoogle = !!customer.google_access_token;

    nextSteps = `
      <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h4>🚀 Next Steps:</h4>
        <div style="background: white; padding: 15px; border-radius: 6px; margin: 10px 0;">
          <strong>Your Customer ID:</strong> 
          <span style="background: #f0f0f0; padding: 8px 12px; border-radius: 4px; font-family: monospace; font-size: 14px;">${customerId}</span>
          <button onclick="copyToClipboard('${customerId}')" style="margin-left: 10px; padding: 6px 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">Copy</button>
        </div>
        
        ${!hasGoogle ? `
          <div style="background: #e3f2fd; padding: 15px; border-radius: 6px; margin: 10px 0; border-left: 4px solid #2196f3;">
            <strong>💡 Enhance Your Integration:</strong>
            <p>Add Google Workspace for even more powerful workflows!</p>
            <a href="/auth/google" style="background: #4285f4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Connect Google Workspace
            </a>
          </div>
        ` : `
          <div style="background: #e8f5e8; padding: 15px; border-radius: 6px; margin: 10px 0; border-left: 4px solid #28a745;">
            <strong>🎉 Fully Integrated!</strong>
            <p>You now have both Google Workspace and QuickBooks connected!</p>
          </div>
        `}
      </div>
    `;
  } else if (googleSuccess && customer) {
    statusMessage = `
      <div style="background: #d4edda; color: #155724; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #28a745;">
        <h3 style="margin-top: 0;">✅ Google Workspace Connected Successfully!</h3>
        <p>Email: <code>${customer.email}</code></p>
      </div>
    `;

    const hasQB = !!(customer.qb_access_token && customer.qb_company_id);

    nextSteps = `
      <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h4>🚀 Next Steps:</h4>
        <div style="background: white; padding: 15px; border-radius: 6px; margin: 10px 0;">
          <strong>Your Customer ID:</strong> 
          <span style="background: #f0f0f0; padding: 8px 12px; border-radius: 4px; font-family: monospace; font-size: 14px;">${customerId}</span>
          <button onclick="copyToClipboard('${customerId}')" style="margin-left: 10px; padding: 6px 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">Copy</button>
        </div>
        
        ${!hasQB ? `
          <div style="background: #fff3cd; padding: 15px; border-radius: 6px; margin: 10px 0; border-left: 4px solid #ffc107;">
            <strong>💡 Add QuickBooks Integration:</strong>
            <p>Connect your accounting data for comprehensive business workflows!</p>
            <a href="/auth/quickbooks/standalone" style="background: #0077C5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Connect QuickBooks
            </a>
          </div>
        ` : `
          <div style="background: #e8f5e8; padding: 15px; border-radius: 6px; margin: 10px 0; border-left: 4px solid #28a745;">
            <strong>🎉 Fully Integrated!</strong>
            <p>You now have both Google Workspace and QuickBooks connected!</p>
          </div>
        `}
      </div>
    `;
  } else {
    const errorMessages = {
      'auth_failed': 'Authorization failed. Please try again.',
      'session_lost': 'Session expired. Please start the authorization process again.',
      'token_save_failed': 'Failed to save authorization tokens. Please try again.'
    };
    statusMessage = `
      <div style="background: #f8d7da; color: #721c24; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #dc3545;">
        <h3 style="margin-top: 0;">❌ Authorization Error</h3>
        <p>${errorMessages[qbError] || 'Unknown error occurred'}</p>
      </div>
    `;

    nextSteps = `
      <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h4>🔄 Try Again:</h4>
        <a href="/" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 5px;">
          Start Over
        </a>
      </div>
    `;
  }

  res.send(`
    <html>
    <head>
      <title>Authorization Result</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .btn { background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 5px; }
        h1 { color: #333; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🤖 AI Workflow Portal</h1>
        
        ${statusMessage}
        ${nextSteps}
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6;">
          <a href="/" class="btn">← Back to Portal</a>
          <a href="/admin" class="btn" style="background: #6c757d;">Admin Panel</a>
        </div>
      </div>
      
      <script>
        function copyToClipboard(text) {
          navigator.clipboard.writeText(text).then(() => {
            alert('Customer ID copied to clipboard!');
          }).catch(err => {
            console.error('Failed to copy:', err);
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            alert('Customer ID copied to clipboard!');
          });
        }
      </script>
    </body>
    </html>
  `);
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) console.error('Logout error:', err);
    res.redirect('/');
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date(), scopes: REQUIRED_SCOPES });
});

app.get('/debug', (req, res) => {
  const protocol = req.header('x-forwarded-proto') || req.protocol;
  const host = req.header('x-forwarded-host') || req.get('host');

  res.json({
    message: "Callback URL Debug",
    detectedProtocol: protocol,
    detectedHost: host,
    detectedCallback: `${protocol}://${host}/auth/google/callback`,
    hardcodedCallback: "https://auth.robosouthla.com/auth/google/callback",
    clientId: process.env.GOOGLE_CLIENT_ID,
    requiredScopes: REQUIRED_SCOPES,
    headers: {
      'x-forwarded-proto': req.header('x-forwarded-proto'),
      'x-forwarded-host': req.header('x-forwarded-host'),
      'host': req.get('host')
    }
  });
});

app.get('/api/customer/:id', async (req, res) => {
  try {
    console.log('API call for customer:', req.params.id);
    const customer = await getCustomerById(req.params.id);

    if (!customer) {
      console.log('Customer not found:', req.params.id);
      return res.status(404).json({
        error: 'customer_not_found',
        message: 'Customer not found. Please authenticate first.',
        authUrl: `https://auth.robosouthla.com/auth/google`
      });
    }

    if (!customer.google_access_token) {
      console.log('No Google token found for:', customer.email);
      return res.status(403).json({
        error: 'no_token',
        message: 'No access token found. Please re-authenticate.',
        authUrl: `https://auth.robosouthla.com/auth/google`
      });
    }

    console.log('Customer found, validating token for:', customer.email);
    console.log('Token starts with:', customer.google_access_token?.substring(0, 20) + '...');

    const tokenValidation = await validateToken(customer.google_access_token);

    console.log('Token validation result:', tokenValidation);

    if (!tokenValidation.valid) {
      console.log('Token validation failed for:', customer.email);
      return res.status(403).json({
        error: 'invalid_token',
        message: 'Access token is invalid or expired. Please re-authenticate.',
        authUrl: `https://auth.robosouthla.com/auth/google`
      });
    }

    const requiredCoreScopes = [
      'https://www.googleapis.com/auth/spreadsheets',
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/calendar',
      'https://www.googleapis.com/auth/drive'
    ];

    const hasRequiredScopes = requiredCoreScopes.some(scope =>
      tokenValidation.scopes.includes(scope)
    );

    if (!hasRequiredScopes && !tokenValidation.scopes.includes('https://www.googleapis.com/auth/spreadsheets.readonly')) {
      return res.status(403).json({
        error: 'insufficient_scope',
        message: 'Token lacks required Google Sheets permissions. Please re-authenticate.',
        required_scopes: REQUIRED_SCOPES,
        current_scopes: tokenValidation.scopes,
        authUrl: `https://auth.robosouthla.com/auth/google`
      });
    }

    res.json({
      id: customer.id,
      email: customer.email,
      name: customer.name,
      accessToken: customer.google_access_token,
      refreshToken: customer.google_refresh_token,
      scopes: tokenValidation.scopes,
      expiresIn: tokenValidation.expires_in,
      createdAt: customer.created_at,
      hasGoogleAuth: true
    });

  } catch (error) {
    console.error('API error:', error);
    res.status(500).json({
      error: 'internal_error',
      message: 'Internal server error'
    });
  }
});


app.get('/api/customers', async (req, res) => {
  try {
    const customers = await getAllCustomers();
    const customerList = customers.map(customer => ({
      id: customer.id,
      email: customer.email,
      name: customer.name,
      hasGoogleAuth: !!customer.google_access_token,
      createdAt: customer.created_at,
      tokenExpiry: customer.token_expiry
    }));
    res.json(customerList);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/customers/latest', async (req, res) => {
  try {
    const customers = await getAllCustomers();
    if (customers.length > 0) {
      const latest = customers[0];
      res.json({
        id: latest.id,
        email: latest.email,
        name: latest.name,
        hasGoogleAuth: !!latest.google_access_token,
        createdAt: latest.created_at
      });
    } else {
      res.status(404).json({ error: 'No customers found' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/customers/count', async (req, res) => {
  try {
    const customers = await getAllCustomers();
    res.json({ count: customers.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/customers/search', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ error: 'Email parameter required' });
    }

    const customers = await getAllCustomers();
    const found = customers.filter(c =>
      c.email.toLowerCase().includes(email.toLowerCase())
    );

    res.json(found.map(customer => ({
      id: customer.id,
      email: customer.email,
      name: customer.name,
      hasGoogleAuth: !!customer.google_access_token,
      hasQuickBooksAuth: !!(customer.qb_access_token && customer.qb_company_id),
      createdAt: customer.created_at,
      tokenExpiry: customer.token_expiry,
      // Optional: Add QB-specific info
      quickbooksInfo: {
        connected: !!(customer.qb_access_token && customer.qb_company_id),
        companyId: customer.qb_company_id || null,
        environment: customer.qb_access_token ? QB_ENVIRONMENT : null
      }
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/auth/quickbooks', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/?error=login_required');
  }

  req.session.customerId = req.user.id;

  const authUri = qbOAuthClient.authorizeUri({
    scope: QB_SCOPES,
    state: crypto.randomBytes(16).toString('hex')
  });

  res.redirect(authUri);
});

// NEW: Standalone QuickBooks auth route (doesn't require Google auth)
app.get('/auth/quickbooks/standalone', (req, res) => {
  // Create a temporary session to track this QB auth attempt
  const tempId = uuidv4();
  req.session.tempQBAuthId = tempId;

  const authUri = qbOAuthClient.authorizeUri({
    scope: QB_SCOPES,
    state: crypto.randomBytes(16).toString('hex')
  });

  console.log('Starting standalone QuickBooks auth with temp ID:', tempId);
  res.redirect(authUri);
});

app.get('/auth/quickbooks/callback', async (req, res) => {
  try {
    if (req.query.error) {
      console.error('QuickBooks OAuth error:', req.query.error);
      return res.redirect('/auth-result?qb_error=auth_failed');
    }

    const authResponse = await qbOAuthClient.createToken(req.url);
    const token = authResponse.getToken();

    console.log('QuickBooks auth successful:', {
      companyId: req.query.realmId,
      hasTokens: !!token.access_token
    });

    const tokenExpiry = new Date(Date.now() + (token.expires_in * 1000));
    const baseUrl = QB_ENVIRONMENT === 'sandbox'
      ? 'https://sandbox-quickbooks.api.intuit.com'
      : 'https://quickbooks.api.intuit.com';

    let customerId;

    // Check if this is a standalone QB auth or existing user QB auth
    if (req.isAuthenticated() && req.user && req.user.id) {
      // Existing authenticated user adding QB - use the authenticated user ID
      customerId = req.user.id;
      console.log('Adding QuickBooks to existing authenticated customer:', customerId);
    } else if (req.session.customerId) {
      // Fallback to session-stored customer ID
      customerId = req.session.customerId;
      console.log('Adding QuickBooks to session customer:', customerId);
    } else if (req.session.tempQBAuthId) {
      // Standalone QB auth - create new customer
      customerId = uuidv4();

      // Create a new customer record with only QB data
      await storeCustomer({
        id: customerId,
        email: `qb-user-${req.query.realmId}@temp.local`, // Temporary email
        name: `QuickBooks User ${req.query.realmId}`,
        picture: null,
        accessToken: null, // No Google token
        refreshToken: null,
        scopes: null,
        tokenExpiry: null,
        qbAccessToken: token.access_token,
        qbRefreshToken: token.refresh_token,
        qbCompanyId: req.query.realmId,
        qbTokenExpiry: tokenExpiry,
        qbBaseUrl: baseUrl
      });

      console.log('Created new QB-only customer:', customerId);

      // Clear the temp session
      delete req.session.tempQBAuthId;
    } else {
      // No session data - redirect to start over
      return res.redirect('/auth-result?qb_error=session_lost');
    }

    // Update QB tokens for the customer
    await updateCustomerQBTokens(customerId, {
      qbAccessToken: token.access_token,
      qbRefreshToken: token.refresh_token,
      qbCompanyId: req.query.realmId,
      qbTokenExpiry: tokenExpiry,
      qbBaseUrl: baseUrl
    });

    // Redirect to success page with customer info
    res.redirect(`/auth-result?qb_success=1&customer_id=${customerId}`);

  } catch (error) {
    console.error('QuickBooks callback error:', error);
    res.redirect('/auth-result?qb_error=token_save_failed');
  }
});

app.post('/auth/quickbooks/disconnect', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    await updateCustomerQBTokens(req.user.id, {
      qbAccessToken: null,
      qbRefreshToken: null,
      qbCompanyId: null,
      qbTokenExpiry: null,
      qbBaseUrl: null
    });

    res.json({ success: true, message: 'QuickBooks disconnected' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to disconnect QuickBooks' });
  }
});

app.get('/auth/quickbooks/disconnect', async (req, res) => {
  try {
    const realmId = req.query.realmId;

    if (realmId) {
      const customers = await getAllCustomers();
      const customer = customers.find(c => c.qb_company_id === realmId);

      if (customer) {
        await updateCustomerQBTokens(customer.id, {
          qbAccessToken: null,
          qbRefreshToken: null,
          qbCompanyId: null,
          qbTokenExpiry: null,
          qbBaseUrl: null
        });

        console.log(`QuickBooks disconnected for customer: ${customer.id} (Company: ${realmId})`);
      }
    }

    res.send(`
      <html>
      <head>
        <title>QuickBooks Disconnected</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
          .container { background: white; padding: 40px; border-radius: 10px; max-width: 500px; margin: 0 auto; }
          .btn { background: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>📊 QuickBooks Disconnected</h1>
          <p>Your QuickBooks integration has been successfully disconnected.</p>
          <p>You can reconnect at any time through your dashboard.</p>
          <a href="/dashboard" class="btn">Go to Dashboard</a>
        </div>
      </body>
      </html>
    `);

  } catch (error) {
    console.error('QuickBooks disconnect error:', error);
    res.redirect('/dashboard?qb_error=disconnect_failed');
  }
});

app.get('/api/customer/:id/quickbooks', async (req, res) => {
  try {
    const customer = await getCustomerById(req.params.id);

    if (!customer) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    if (!customer.qb_access_token) {
      return res.json({
        connected: false,
        message: 'QuickBooks not connected'
      });
    }

    const validation = await validateQBToken(customer.qb_access_token, customer.qb_company_id);

    res.json({
      connected: validation.valid,
      companyId: customer.qb_company_id,
      baseUrl: customer.qb_base_url,
      environment: QB_ENVIRONMENT,
      tokenValid: validation.valid,
      tokenExpiry: customer.qb_token_expiry
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/customer/:id/quickbooks/tokens', async (req, res) => {
  try {
    const customer = await getCustomerById(req.params.id);

    if (!customer) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    if (!customer.qb_access_token) {
      return res.status(403).json({
        error: 'quickbooks_not_connected',
        message: 'QuickBooks not connected. Please authorize first.',
        authUrl: `https://auth.robosouthla.com/auth/quickbooks`
      });
    }

    res.json({
      accessToken: customer.qb_access_token,
      refreshToken: customer.qb_refresh_token,
      companyId: customer.qb_company_id,
      baseUrl: customer.qb_base_url,
      environment: QB_ENVIRONMENT,
      tokenExpiry: customer.qb_token_expiry
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/terms', (req, res) => {
  res.send(`
    <html>
    <head>
      <title>Terms of Service - RoboSouth LA</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; line-height: 1.6; }
        h1, h2 { color: #333; }
        .container { background: white; padding: 30px; border-radius: 10px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Terms of Service</h1>
        <p><strong>Effective Date:</strong> 6/8/2025</p>
        <p><strong>Last Updated:</strong> 6/8/2025</p>
        
        <p>These Terms of Service ("Terms") govern your access to and use of the services, platform, website, and any associated software provided by RoboSouth LA ("Company," "we," "us," or "our") via https://www.robosouthla.com ("Site").</p>
        
        <p>By using our services, you ("Customer," "User," or "You") agree to be bound by these Terms.</p>
        
        <h2>QuickBooks Integration</h2>
        <p>When connecting QuickBooks Online, you authorize us to access your company's accounting data including invoices, customers, vendors, and financial reports for business automation purposes only.</p>
        
        <p><strong>Contact:</strong> info@robosouthla.com</p>
        <p><a href="/dashboard">← Back to Dashboard</a></p>
      </div>
    </body>
    </html>
  `);
});

app.get('/privacy', (req, res) => {
  res.send(`
    <html>
    <head>
      <title>Privacy Policy - RoboSouth LA</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; line-height: 1.6; }
        h1, h2 { color: #333; }
        .container { background: white; padding: 30px; border-radius: 10px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Privacy Policy</h1>
        <p><strong>Effective Date:</strong> 6/8/2025</p>
        <p><strong>Last Updated:</strong> 6/8/2025</p>
        
        <h2>Who We Are</h2>
        <p>RoboSouth LA operates a workflow automation platform accessible at https://www.robosouthla.com, offering automation services and integrations, including support for third-party platforms such as Google Workspace and QuickBooks Online.</p>
        
        <h2>QuickBooks Data</h2>
        <p>When you connect QuickBooks Online, we may access company information, customer data, invoices, and financial reports solely to enable your authorized business automation workflows. This data is encrypted and never shared with third parties.</p>
        
        <p><strong>Contact:</strong> privacy@robosouthla.com</p>
        <p><a href="/dashboard">← Back to Dashboard</a></p>
      </div>
    </body>
    </html>
  `);
});

// Delete customer route
app.delete('/admin/customer/:id', async (req, res) => {
  try {
    const customerId = req.params.id;

    // Get customer info before deleting for logging
    const customer = await getCustomerById(customerId);

    await new Promise((resolve, reject) => {
      db.run('DELETE FROM customers WHERE id = ?', [customerId], function (err) {
        if (err) reject(err);
        else resolve(this.changes);
      });
    });

    console.log(`Customer deleted: ${customer ? customer.email : customerId}`);

    res.json({
      success: true,
      message: `Customer deleted successfully`,
      customerEmail: customer ? customer.email : 'Unknown'
    });
  } catch (error) {
    console.error('Delete customer error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/auth/google/disconnect', async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const customerId = req.user.id;
    console.log('Disconnecting Google for user:', req.user.email);

    // Remove Google tokens from database
    const stmt = db.prepare(`
      UPDATE customers 
      SET google_access_token = NULL, 
          google_refresh_token = NULL, 
          scopes = NULL, 
          token_expiry = NULL,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `);

    stmt.run([customerId], function (err) {
      if (err) {
        console.error('Error disconnecting Google:', err);
        return res.status(500).json({ error: 'Failed to disconnect' });
      }

      console.log('Google disconnected successfully for:', req.user.email);
      res.redirect('/dashboard?google_disconnected=1');
    });

  } catch (error) {
    console.error('Disconnect error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/admin', async (req, res) => {
  try {
    const customers = await getAllCustomers();

    const customerRows = await Promise.all(customers.map(async customer => {
      let googleTokenStatus = 'Unknown';
      if (customer.google_access_token) {
        const validation = await validateToken(customer.google_access_token);
        googleTokenStatus = validation.valid ? `Valid (${validation.expires_in}s)` : 'Invalid/Expired';
      }

      let qbTokenStatus = 'Not Connected';
      if (customer.qb_access_token && customer.qb_company_id) {
        const qbValidation = await validateQBToken(customer.qb_access_token, customer.qb_company_id);
        qbTokenStatus = qbValidation.valid ? 'Connected' : 'Invalid/Expired';
      }

      return `<tr>
        <td><code style="font-size:12px;">${customer.id}</code></td>
        <td>${customer.email}</td>
        <td>${customer.name}</td>
        <td>
          <span style="padding:2px 8px;border-radius:12px;font-size:11px;background:${googleTokenStatus.includes('Valid') ? '#e8f5e8;color:#2d5a2d' : '#ffeaea;color:#d32f2f'}">${googleTokenStatus}</span>
        </td>
        <td>
          <span style="padding:2px 8px;border-radius:12px;font-size:11px;background:${qbTokenStatus === 'Connected' ? '#e8f5e8;color:#2d5a2d' : qbTokenStatus === 'Not Connected' ? '#f0f0f0;color:#666' : '#ffeaea;color:#d32f2f'}">${qbTokenStatus}</span>
          ${customer.qb_company_id ? `<br><small style="color:#666;">Company: ${customer.qb_company_id}</small>` : ''}
        </td>
        <td>${new Date(customer.created_at).toLocaleDateString()}</td>
        <td>
          <button onclick="copyToClipboard('${customer.id}')" 
                  style="padding:5px 10px;background:#7c3aed;color:white;border:none;border-radius:4px;cursor:pointer;margin:2px;font-size:11px;">
            Copy Customer ID
          </button><br>
          <button onclick="copyToClipboard('${customer.google_access_token || 'N/A'}')" 
                  style="padding:5px 10px;background:#4285f4;color:white;border:none;border-radius:4px;cursor:pointer;margin:2px;font-size:11px;">
            Copy Google Token
          </button><br>
          ${customer.qb_access_token ? `
          <button onclick="copyToClipboard('${customer.qb_access_token}')" 
                  style="padding:5px 10px;background:#0077C5;color:white;border:none;border-radius:4px;cursor:pointer;margin:2px;font-size:11px;">
            Copy QB Token
          </button><br>` : `
          <span style="font-size:11px;color:#999;">No QB Token</span><br>
          `}
          <button onclick="deleteCustomer('${customer.id}', '${customer.email}')" 
                  style="padding:5px 10px;background:#dc3545;color:white;border:none;border-radius:4px;cursor:pointer;margin:2px;font-size:11px;">
            Delete Customer
          </button>
        </td>
      </tr>`;
    }));




    const connectedCustomers = customers.filter(c => c.google_access_token && c.qb_access_token).length;
    const googleOnlyCustomers = customers.filter(c => c.google_access_token && !c.qb_access_token).length;
    const qbOnlyCustomers = customers.filter(c => !c.google_access_token && c.qb_access_token).length;

    res.send(`
      <html>
      <head>
        <title>Admin - Customer Management</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5; }
          .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
          table { width: 100%; border-collapse: collapse; background: white; margin: 20px 0; }
          th, td { padding: 8px; text-align: left; border: 1px solid #ddd; font-size: 13px; }
          th { background-color: #f9fafb; font-weight: 600; }
          .btn { background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; }
          .info-box { background: #f0f9ff; padding: 20px; border-radius: 8px; margin: 20px 0; }
          .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
          .stat-card { background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; border-left: 4px solid #007bff; }
          .stat-number { font-size: 24px; font-weight: bold; color: #333; }
          .stat-label { font-size: 12px; color: #666; text-transform: uppercase; margin-top: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>👥 Customer Management Dashboard</h1>
          
          <div class="stats-grid">
            <div class="stat-card">
              <div class="stat-number">${customers.length}</div>
              <div class="stat-label">Total Customers</div>
            </div>
            <div class="stat-card" style="border-left-color: #28a745;">
              <div class="stat-number">${connectedCustomers}</div>
              <div class="stat-label">Fully Connected</div>
            </div>
            <div class="stat-card" style="border-left-color: #4285f4;">
              <div class="stat-number">${googleOnlyCustomers}</div>
              <div class="stat-label">Google Only</div>
            </div>
            <div class="stat-card" style="border-left-color: #0077C5;">
              <div class="stat-number">${qbOnlyCustomers}</div>
              <div class="stat-label">QuickBooks Only</div>
            </div>
          </div>
          
          <div class="info-box">
            <h3>🔗 Integration Status Overview</h3>
            <p><strong>Fully Connected:</strong> Customers with both Google and QuickBooks authorization</p>
            <p><strong>Available Integrations:</strong></p>
            <ul style="text-align: left;">
              <li><strong>Google Workspace:</strong> Sheets, Gmail, Calendar, Contacts, Drive</li>
              <li><strong>QuickBooks:</strong> Accounting data access (Environment: ${QB_ENVIRONMENT})</li>
            </ul>
          </div>
          
          <table>
            <thead>
              <tr>
                <th>Customer ID</th>
                <th>Email</th>
                <th>Name</th>
                <th>Google Status</th>
                <th>QuickBooks Status</th>
                <th>Registered</th>
                <th>API Integration</th>
              </tr>
            </thead>
            <tbody>
              ${customerRows.join('')}
            </tbody>
          </table>
          
          <div class="info-box">
            <h3>🔧 N8N Integration Guide</h3>
            <ol>
              <li><strong>Copy Customer ID</strong> from the table above</li>
              <li><strong>Google API:</strong> Use <code>GET /api/customer/{id}</code> for Google tokens</li>
              <li><strong>QuickBooks API:</strong> Use <code>GET /api/customer/{id}/quickbooks/tokens</code> for QB tokens</li>
              <li><strong>Status Check:</strong> Use <code>GET /api/customer/{id}/quickbooks</code> to verify QB connection</li>
            </ol>
            
            <h4>Environment Variables Needed:</h4>
            <ul style="font-family: monospace; font-size: 13px; background: #f8f9fa; padding: 15px; border-radius: 6px;">
              <li>QB_CLIENT_ID=your_quickbooks_app_id</li>
              <li>QB_CLIENT_SECRET=your_quickbooks_app_secret</li>
              <li>NODE_ENV=production (for production QB environment)</li>
            </ul>
          </div>
          
          <br><a href="/" class="btn">← Back to Portal</a>
        </div>
        
        <script>
          function copyToClipboard(text) {
            if (text === 'N/A') {
              alert('No token available');
              return;
            }
            navigator.clipboard.writeText(text).then(() => {
              alert('Copied to clipboard!');
            }).catch(err => {
              const textArea = document.createElement('textarea');
              textArea.value = text;
              document.body.appendChild(textArea);
              textArea.select();
              document.execCommand('copy');
              document.body.removeChild(textArea);
              alert('Copied to clipboard!');
            });
          }

          async function deleteCustomer(customerId, customerEmail) {
            if (!confirm(\`Are you sure you want to delete customer: \${customerEmail}?\\n\\nCustomer ID: \${customerId}\\n\\nThis action cannot be undone.\`)) {
              return;
            }
            
            try {
              const response = await fetch(\`/admin/customer/\${customerId}\`, {
                method: 'DELETE',
                headers: {
                  'Content-Type': 'application/json'
                }
              });
              
              const result = await response.json();
              
              if (response.ok) {
                alert(\`Customer \${result.customerEmail} deleted successfully!\`);
                location.reload();
              } else {
                alert('Failed to delete customer: ' + result.error);
              }
            } catch (error) {
              alert('Error deleting customer: ' + error.message);
            }
          }
        </script>
      </body>
      </html>
    `);
  } catch (error) {
    res.status(500).send('Error loading customers: ' + error.message);
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Portal running on port ${PORT}`);
  console.log('Callback URL: https://auth.robosouthla.com/auth/google/callback');
  console.log('Required scopes:', REQUIRED_SCOPES.join(', '));
});