/**
 * CSRF Protection Middleware
 * 
 * Implements Double Submit Cookie pattern for CSRF protection:
 * 1. Backend generates a random CSRF token and sends it as a non-httpOnly cookie
 * 2. Frontend reads this cookie and includes it in X-CSRF-Token header
 * 3. Backend validates that the header matches the cookie
 * 
 * This works alongside HttpOnly session cookies for complete security.
 */

import crypto from 'crypto';

// ============================================
// CONFIGURATION
// ============================================

const CSRF_COOKIE_NAME = 'csrf_token';
const CSRF_HEADER_NAME = 'x-csrf-token';
const TOKEN_LENGTH = 32; // 256 bits
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

const isProduction = process.env.NODE_ENV === 'production';

// ============================================
// TOKEN GENERATION
// ============================================

/**
 * Generate a cryptographically secure CSRF token
 */
const generateToken = () => {
    return crypto.randomBytes(TOKEN_LENGTH).toString('hex');
};

// ============================================
// CSRF COOKIE SETTINGS
// ============================================

const getCookieOptions = () => ({
    httpOnly: false, // MUST be false so frontend JavaScript can read it
    secure: isProduction, // HTTPS only in production
    sameSite: isProduction ? 'strict' : 'lax',
    path: '/',
    maxAge: TOKEN_EXPIRY_MS,
    domain: process.env.COOKIE_DOMAIN || undefined,
});

// ============================================
// SET CSRF TOKEN
// ============================================

/**
 * Middleware to set CSRF token cookie on every request
 * This ensures the frontend always has a valid CSRF token
 */
export const setCsrfToken = (req, res, next) => {
    // Check if CSRF token already exists in cookies
    let token = req.cookies?.[CSRF_COOKIE_NAME];

    // Generate new token if none exists
    if (!token) {
        token = generateToken();
    }

    // Set/refresh the CSRF cookie
    res.cookie(CSRF_COOKIE_NAME, token, getCookieOptions());

    // Attach token to request for use in API responses
    req.csrfToken = token;

    next();
};

// ============================================
// CSRF TOKEN ENDPOINT
// ============================================

/**
 * Endpoint handler to get a fresh CSRF token
 * GET /api/csrf-token
 * 
 * SECURITY FIX: Token is NO LONGER returned in the JSON response body.
 * The token is ONLY sent via the non-HttpOnly cookie.
 * 
 * This properly implements the Double Submit Cookie pattern:
 * 1. Backend sets token in non-HttpOnly cookie (accessible to JavaScript)
 * 2. Frontend reads cookie and sends token in X-CSRF-Token header
 * 3. Backend validates that header matches cookie
 * 
 * Returning the token in the response body defeats the purpose of the pattern
 * as it could be captured by malicious scripts in certain attack scenarios.
 */
export const getCsrfTokenHandler = (req, res) => {
    // Generate fresh token
    const token = generateToken();

    // Set the cookie (non-HttpOnly so JavaScript can read it)
    res.cookie(CSRF_COOKIE_NAME, token, getCookieOptions());

    // ============================================
    // SECURITY FIX: Do NOT return token in response body
    // The frontend must read it from the cookie instead
    // ============================================
    res.status(200).json({
        success: true,
        message: 'CSRF token refreshed. Read the token from the csrf_token cookie.',
        // SECURITY: Token intentionally omitted from response body
        // csrfToken: token,  // <-- REMOVED for security
    });
};

// ============================================
// VALIDATE CSRF TOKEN
// ============================================

/**
 * Middleware to validate CSRF token on state-changing requests
 * Only applies to POST, PUT, PATCH, DELETE methods
 */
export const validateCsrfToken = (req, res, next) => {
    // Skip validation for safe methods
    const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
    if (safeMethods.includes(req.method)) {
        return next();
    }

    // Skip validation for webhook endpoints (they use their own authentication)
    if (req.path.includes('/webhook')) {
        return next();
    }

    // ============================================
    // SECURITY FIX: Removed multipart/form-data exemption
    // 
    // VULNERABILITY FIXED: Previously, CSRF validation was skipped for all
    // multipart/form-data requests. This allowed attackers to craft malicious
    // forms that bypass CSRF protection on file upload endpoints.
    //
    // The frontend MUST include the CSRF token in the X-CSRF-Token header
    // for ALL state-changing requests, including file uploads.
    //
    // REMOVED CODE:
    // const contentType = req.headers['content-type'] || '';
    // if (contentType.includes('multipart/form-data')) {
    //     return next();
    // }
    // ============================================

    // Get token from cookie
    const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];

    // Get token from header
    const headerToken = req.headers[CSRF_HEADER_NAME];

    // Validate: both must exist and match
    if (!cookieToken) {
        console.warn('[CSRF] No CSRF cookie found', { path: req.path, ip: req.ip });
        return res.status(403).json({
            success: false,
            message: 'CSRF validation failed. Please refresh the page and try again.',
            code: 'CSRF_MISSING_COOKIE',
        });
    }

    if (!headerToken) {
        console.warn('[CSRF] No CSRF header found', { path: req.path, ip: req.ip });
        return res.status(403).json({
            success: false,
            message: 'CSRF validation failed. Please refresh the page and try again.',
            code: 'CSRF_MISSING_HEADER',
        });
    }

    // Constant-time comparison to prevent timing attacks
    if (!crypto.timingSafeEqual(Buffer.from(cookieToken), Buffer.from(headerToken))) {
        console.warn('[CSRF] Token mismatch', { path: req.path, ip: req.ip });
        return res.status(403).json({
            success: false,
            message: 'CSRF validation failed. Please refresh the page and try again.',
            code: 'CSRF_TOKEN_MISMATCH',
        });
    }

    // Token is valid
    next();
};

// ============================================
// COMBINED MIDDLEWARE
// ============================================

/**
 * Combined middleware that:
 * 1. Sets CSRF token cookie on all requests
 * 2. Validates CSRF token on state-changing requests
 */
export const csrfProtection = (req, res, next) => {
    // First, ensure CSRF cookie is set
    setCsrfToken(req, res, () => {
        // Then validate on state-changing requests
        validateCsrfToken(req, res, next);
    });
};

// Default export
export default {
    setCsrfToken,
    getCsrfTokenHandler,
    validateCsrfToken,
    csrfProtection,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
};
