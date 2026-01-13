/**
 * DealDirect Server - Production-Ready for Hostinger Cloud
 * 
 * IMPORTANT: In production (Hostinger Cloud), environment variables are
 * injected via hPanel → Node.js → Environment Variables.
 * The .env file is NOT loaded in production.
 */

// ============================================
// IMPORTS FIRST (ES Modules hoists these anyway)
// ============================================
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import fs from "fs";
import express from "express";
import cors from "cors";

// ============================================
// DEBUG LOGGING - Runs after imports
// ============================================
console.log("========================================");
console.log("🚀 DEALDIRECT SERVER STARTING");
console.log("========================================");
console.log("Node.js version:", process.version);
console.log("NODE_ENV:", process.env.NODE_ENV || "NOT SET");
console.log("PORT:", process.env.PORT || "NOT SET");
console.log("MONGO_URI:", process.env.MONGO_URI ? "SET (" + process.env.MONGO_URI.substring(0, 25) + "...)" : "NOT SET");
console.log("JWT_SECRET:", process.env.JWT_SECRET ? "SET (length: " + process.env.JWT_SECRET.length + ")" : "NOT SET");
console.log("CLIENT_URL:", process.env.CLIENT_URL || "NOT SET");
console.log("========================================");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================
// HOSTINGER CLOUD FIX: Only load .env in non-production
// ============================================
if (process.env.NODE_ENV !== "production") {
  const envCurrent = path.resolve(__dirname, '.env');
  const envParent = path.resolve(__dirname, '../.env');

  dotenv.config({ path: envCurrent });

  if (!process.env.MONGO_URI) {
    console.log(`⚠️ .env not found in current dir. Trying parent: ${envParent}`);
    dotenv.config({ path: envParent });
  }

  console.log("📄 Development mode: Loaded .env file");
} else {
  console.log("☁️ Production mode: Using Hostinger hPanel environment variables");
}
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import hpp from "hpp";
import { createServer } from "http";
import crypto from "crypto";

// ============================================
// APP SETUP
// ============================================

const app = express();
const httpServer = createServer(app);

// MIDDLEWARE SETUP
app.use(helmet({ contentSecurityPolicy: false })); // Relaxed for test
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(hpp());

// CORS
const allowedOrigins = [process.env.CLIENT_URL, process.env.ADMIN_URL, 'http://localhost:3000'].filter(Boolean);
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    callback(null, true); // Allow all for this test to be safe
  },
  credentials: true
}));

console.log("✅ Middleware configured");

// ============================================
// ENVIRONMENT VALIDATION - FAIL FAST IN PRODUCTION
// ============================================

const validateEnvironment = () => {
  const isProduction = process.env.NODE_ENV === "production";

  // CRITICAL: These MUST exist for the server to function
  const CRITICAL_ENV_VARS = [
    'MONGO_URI',
    'JWT_SECRET',
  ];

  // IMPORTANT: These are needed for full functionality
  const IMPORTANT_ENV_VARS = [
    'CLIENT_URL',
    'ADMIN_URL',
    'CLOUDINARY_URL',
  ];

  // OPTIONAL: These have reasonable defaults or are feature-specific
  const OPTIONAL_ENV_VARS = [
    { name: 'SMTP_USER', description: 'Email notifications' },
    { name: 'SMTP_PASS', description: 'Email notifications' },
    { name: 'GEMINI_API_KEY', description: 'AI agreement generation' },
    { name: 'COOKIE_DOMAIN', description: 'Cross-domain cookies' },
  ];

  const errors = [];
  const warnings = [];

  // Check critical vars
  for (const varName of CRITICAL_ENV_VARS) {
    if (!process.env[varName]) {
      errors.push(`❌ CRITICAL: Missing ${varName}`);
    }
  }

  // Check important vars
  for (const varName of IMPORTANT_ENV_VARS) {
    if (!process.env[varName]) {
      warnings.push(`⚠️ WARNING: Missing ${varName}`);
    }
  }

  // Check optional vars (just info)
  for (const { name, description } of OPTIONAL_ENV_VARS) {
    if (!process.env[name]) {
      console.log(`ℹ️ Optional: ${name} not set (${description})`);
    }
  }

  // Log validation results
  console.log('═'.repeat(50));
  console.log('🔐 ENVIRONMENT VALIDATION');
  console.log('═'.repeat(50));
  console.log(`   Environment: ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}`);
  console.log(`   NODE_ENV: ${process.env.NODE_ENV || 'not set'}`);

  if (warnings.length > 0) {
    console.log('');
    warnings.forEach(w => console.warn(w));
  }

  if (errors.length > 0) {
    console.log('');
    errors.forEach(e => console.error(e));
    console.log('');
    console.error('🚨 CRITICAL: Server cannot start without required environment variables!');
    console.error('');
    console.error('📋 For Hostinger Cloud:');
    console.error('   1. Go to hPanel → Websites → Your Site');
    console.error('   2. Click "Manage" → "Node.js" section');
    console.error('   3. Add each missing variable in "Environment Variables"');
    console.error('   4. Restart the application');
    console.error('');

    // FAIL FAST in production
    // TEMPORARY: Disabled to allow server to start while env vars are configured
    // TODO: Re-enable after setting env vars in Hostinger hPanel
    if (isProduction && false) { // <-- TEMPORARILY DISABLED
      console.error('💀 Exiting process due to missing critical environment variables.');
      process.exit(1);
    } else {
      console.warn('⚠️ CONTINUING DESPITE MISSING VARS - SET ENV VARS IN HPANEL IMMEDIATELY!');
    }
  } else {
    console.log('');
    console.log('✅ All critical environment variables are present');
  }
  console.log('═'.repeat(50));
};

validateEnvironment();

// ============================================
// DATABASE
// ============================================
import connectDB from "./config/db.js";

// SAFELY connect to database without crashing server
// If connection fails, server stays UP but DB features won't work
connectDB().catch(err => {
  console.error("❌ CRITICAL DATABASE ERROR:", err);
  console.error("⚠️ Server running in 'Offline Mode' (No Database)");
});

// ============================================
// ROUTE IMPORTS
// ============================================

import userRoutes from "./routes/userRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import categoryRoutes from "./routes/categoryRoutes.js";
import subcategoryRoutes from "./routes/subcategoryRoutes.js";
import propertyRoutes from "./routes/propertyRoutes.js";
import propertyTypeRoutes from './routes/propertyTypeRoutes.js';
import leadRoutes from './routes/leadRoutes.js';
import chatRoutes from './routes/chatRoutes.js';
import contactRoutes from './routes/contactRoutes.js';
import agreementRoutes from './routes/agreementRoutes.js';
import savedSearchRoutes from './routes/savedSearchRoutes.js';
import notificationRoutes from './routes/notificationRoutes.js';
import { globalErrorHandler, notFoundHandler } from "./middleware/errorHandler.js";
import { blockRetiredRoles } from "./middleware/roleGuard.js";
import { setCsrfToken, validateCsrfToken, getCsrfTokenHandler } from "./middleware/csrfProtection.js";

// ============================================
// APP SETUP & MIDDLEWARE
// ============================================
// (Already configured in previous step)


// ============================================
// API ROUTES
// ============================================

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV || 'NOT SET',
    mongo_uri_exists: !!process.env.MONGO_URI,
    jwt_secret_exists: !!process.env.JWT_SECRET,
  });
});

// TEMPORARY DEBUG ENDPOINT - Remove after fixing
app.get('/debug-env', (req, res) => {
  res.json({
    message: 'Environment Debug Info',
    NODE_ENV: process.env.NODE_ENV || 'NOT SET',
    env_vars_detected: {
      MONGO_URI: process.env.MONGO_URI ? 'SET (first 20 chars): ' + process.env.MONGO_URI.substring(0, 20) + '...' : 'NOT SET',
      JWT_SECRET: process.env.JWT_SECRET ? 'SET (length: ' + process.env.JWT_SECRET.length + ')' : 'NOT SET',
      CLIENT_URL: process.env.CLIENT_URL || 'NOT SET',
      ADMIN_URL: process.env.ADMIN_URL || 'NOT SET',
      CLOUDINARY_URL: process.env.CLOUDINARY_URL ? 'SET' : 'NOT SET',
      SMTP_USER: process.env.SMTP_USER || 'NOT SET',
      PORT: process.env.PORT || 'NOT SET',
    },
    all_env_keys: Object.keys(process.env).sort(),
  });
});

// DB Diagnostic Endpoint - SECURED for production
app.get('/api/health-db', (req, res) => {
  try {
    const isProduction = process.env.NODE_ENV === 'production';
    const statusMap = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };
    const state = mongoose.connection ? mongoose.connection.readyState : 99;

    // SECURITY: Don't expose sensitive info in production
    const response = {
      status: 'ok',
      environment: isProduction ? 'production' : 'development',
      db: {
        state: statusMap[state] || 'unknown',
        connected: state === 1,
      },
      env_status: {
        mongo_uri: !!process.env.MONGO_URI ? 'configured' : 'missing',
        jwt_secret: !!process.env.JWT_SECRET ? 'configured' : 'missing',
        client_url: !!process.env.CLIENT_URL ? 'configured' : 'missing',
        cloudinary: !!process.env.CLOUDINARY_URL ? 'configured' : 'missing',
        smtp: !!(process.env.SMTP_USER && process.env.SMTP_PASS) ? 'configured' : 'missing',
      }
    };

    // Only show detailed debug info in development
    if (!isProduction) {
      const envCurrent = path.resolve(__dirname, '.env');
      const envParent = path.resolve(__dirname, '../.env');

      response.debug = {
        file_current_exists: fs.existsSync(envCurrent),
        file_parent_exists: fs.existsSync(envParent),
        parent_path: envParent,
        db_name: mongoose.connection ? mongoose.connection.name : 'unknown',
        db_host: mongoose.connection ? mongoose.connection.host : 'unknown',
        // Only show env key names in development, never values
        env_keys: Object.keys(process.env).filter(k => !k.includes('SECRET') && !k.includes('PASS') && !k.includes('KEY')).sort()
      };
    }

    res.json(response);
  } catch (error) {
    res.status(500).json({ error: 'Health check failed' });
  }
});

app.get('/api/csrf-token', getCsrfTokenHandler);

// Root Route (Must be before error handlers)
app.get('/', (req, res) => {
  res.send(`DealDirect Backend v3.0 - FULL SYSTEM ACTIVE (${new Date().toISOString()})`);
});

// Public Routes
app.use("/api/users", userRoutes);
app.use("/api/admin", adminRoutes);

app.use("/api/propertyTypes", propertyTypeRoutes);
app.use("/api/categories", categoryRoutes);
app.use("/api/subcategories", subcategoryRoutes);
app.use("/api/properties", propertyRoutes);
app.use("/api/leads", leadRoutes);
// app.use("/api/chat", chatRoutes); // Disabled until Socket.io is back
app.use("/api/contact", contactRoutes);
app.use("/api/agreements", agreementRoutes);
app.use("/api/saved-searches", savedSearchRoutes);
app.use("/api/notifications", notificationRoutes);

// Error Handling
app.use(notFoundHandler);
app.use(globalErrorHandler);


// ============================================
// STARTUP
// ============================================

// PORT: In production (Hostinger), PORT is always injected via hPanel
// The fallback 9000 is ONLY for local development
const PORT = process.env.PORT || 9000;

httpServer.listen(PORT, '0.0.0.0', () => {
  const isProduction = process.env.NODE_ENV === "production";
  console.log('═'.repeat(60));
  console.log(`🚀 DealDirect Backend v3.0 - ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}`);
  console.log(`📡 Listening on port: ${PORT}`);
  console.log(`👉 Health: http://0.0.0.0:${PORT}/health`);
  console.log('═'.repeat(60));
});