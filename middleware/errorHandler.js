/**
 * Global Error Handling Middleware - Production Hardened
 * 
 * SECURITY FEATURES:
 * - Zero internal information leakage in production
 * - Full server-side logging with stack traces
 * - Request ID for support referencing
 * - Safe error messages for clients
 */

import crypto from 'crypto';

// ============================================
// CUSTOM ERROR CLASS
// ============================================

export class AppError extends Error {
    constructor(message, statusCode, code = 'ERROR') {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.isOperational = true; // Distinguishes operational errors from programming errors
        this.timestamp = new Date().toISOString();

        Error.captureStackTrace(this, this.constructor);
    }
}

// ============================================
// ERROR CODES - Safe Messages for Clients
// ============================================

const ERROR_CODES = {
    VALIDATION_ERROR: { status: 400, message: 'Invalid request data' },
    BAD_REQUEST: { status: 400, message: 'Invalid request' },
    UNAUTHORIZED: { status: 401, message: 'Authentication required' },
    INVALID_TOKEN: { status: 401, message: 'Session expired' },
    TOKEN_EXPIRED: { status: 401, message: 'Session expired' },
    FORBIDDEN: { status: 403, message: 'Access denied' },
    NOT_FOUND: { status: 404, message: 'Resource not found' },
    CONFLICT: { status: 409, message: 'Resource conflict' },
    RATE_LIMITED: { status: 429, message: 'Too many requests' },
    SERVER_ERROR: { status: 500, message: 'Internal server error' },
};

// ============================================
// PRODUCTION SAFE MESSAGES
// These are the ONLY messages that will be sent in production
// ============================================

const PRODUCTION_MESSAGES = {
    400: 'Bad request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not found',
    409: 'Conflict',
    429: 'Too many requests',
    500: 'Internal server error',
    502: 'Service temporarily unavailable',
    503: 'Service temporarily unavailable',
};

// ============================================
// SECURITY: Sensitive keys to redact from query/headers
// ============================================

const SENSITIVE_QUERY_KEYS = [
    'token', 'access_token', 'refresh_token', 'session', 'sessionToken',
    'auth', 'authorization', 'api_key', 'apiKey', 'key',
    'password', 'secret', 'signature', 'sig',
    'otp', 'code', 'verificationCode',
    'email', 'phone', 'mobile',
];

const SENSITIVE_HEADER_KEYS = [
    'authorization', 'cookie', 'set-cookie',
    'x-api-key', 'x-auth-token', 'x-session-id', 'x-csrf-token',
    'x-forwarded-for', // Contains IP addresses
];

/**
 * SECURITY FIX: Sanitize query parameters for logging
 * Redacts sensitive keys that may contain PII or session identifiers
 */
const sanitizeQueryForLogging = (query) => {
    if (!query || typeof query !== 'object') return query;

    const sanitized = {};
    for (const [key, value] of Object.entries(query)) {
        const keyLower = key.toLowerCase();
        // Check if key is sensitive
        const isSensitive = SENSITIVE_QUERY_KEYS.some(sensitive =>
            keyLower.includes(sensitive.toLowerCase())
        );
        sanitized[key] = isSensitive ? '[REDACTED]' : value;
    }
    return sanitized;
};

/**
 * SECURITY FIX: Sanitize headers for logging
 * Redacts sensitive headers that may contain auth tokens or session data
 */
const sanitizeHeadersForLogging = (headers) => {
    if (!headers || typeof headers !== 'object') return {};

    const sanitized = {};
    for (const [key, value] of Object.entries(headers)) {
        const keyLower = key.toLowerCase();
        // Check if header is sensitive
        const isSensitive = SENSITIVE_HEADER_KEYS.some(sensitive =>
            keyLower === sensitive.toLowerCase()
        );
        // For sensitive headers, only indicate presence, not value
        if (isSensitive) {
            sanitized[key] = value ? '[PRESENT - REDACTED]' : '[NOT PRESENT]';
        } else {
            sanitized[key] = value;
        }
    }
    return sanitized;
};

// ============================================
// ERROR LOGGING - Full Details Server-Side
// ============================================

const logError = (err, req) => {
    const timestamp = new Date().toISOString();
    const requestId = req.requestId || crypto.randomBytes(8).toString('hex');

    // ============================================
    // SECURITY FIX: Sanitize query and headers before logging
    // Prevents PII and session identifiers from being logged
    // ============================================
    const context = {
        requestId,
        timestamp,
        method: req.method,
        path: req.path,
        originalUrl: req.originalUrl,
        // SECURITY: Sanitize query parameters
        query: sanitizeQueryForLogging(req.query),
        // Sanitize body for logging (remove sensitive fields)
        body: sanitizeBodyForLogging(req.body),
        userId: req.user?._id?.toString() || 'anonymous',
        userRole: req.user?.role || 'none',
        ip: getClientIP(req),
        // SECURITY: Only log User-Agent, not full headers
        userAgent: req.get('User-Agent')?.substring(0, 200),
    };

    // Full error details
    const errorDetails = {
        name: err.name,
        message: err.message,
        code: err.code,
        statusCode: err.statusCode,
        isOperational: err.isOperational,
        stack: err.stack,
    };

    // Log to console (in production, this should be captured by a log aggregator)
    console.error('\n' + '═'.repeat(70));
    console.error(`[ERROR] ${timestamp} | Request ID: ${requestId}`);
    console.error('─'.repeat(70));
    console.error('REQUEST CONTEXT:');
    console.error(JSON.stringify(context, null, 2));
    console.error('─'.repeat(70));
    console.error('ERROR DETAILS:');
    console.error(`  Name: ${errorDetails.name}`);
    console.error(`  Message: ${errorDetails.message}`);
    console.error(`  Code: ${errorDetails.code || 'N/A'}`);
    console.error(`  Status: ${errorDetails.statusCode || 500}`);
    console.error(`  Operational: ${errorDetails.isOperational ? 'Yes' : 'No (Programming Error)'}`);
    console.error('─'.repeat(70));
    console.error('STACK TRACE:');
    console.error(errorDetails.stack);

    // Log validation errors if present
    if (err.errors) {
        console.error('─'.repeat(70));
        console.error('VALIDATION ERRORS:');
        console.error(JSON.stringify(err.errors, null, 2));
    }

    console.error('═'.repeat(70) + '\n');

    return requestId;
};

/**
 * Remove sensitive fields from body before logging
 */
const sanitizeBodyForLogging = (body) => {
    if (!body || typeof body !== 'object') return body;

    const sensitiveFields = [
        'password', 'confirmPassword', 'currentPassword', 'newPassword',
        'aadhaar', 'landlordAadhaar', 'tenantAadhaar',
        'otp', 'token', 'refreshToken', 'accessToken',
        'secret', 'apiKey', 'privateKey',
        'creditCard', 'cardNumber', 'cvv', 'pin',
    ];

    const sanitized = { ...body };
    for (const field of sensitiveFields) {
        if (sanitized[field]) {
            sanitized[field] = '[REDACTED]';
        }
    }

    return sanitized;
};

/**
 * Get real client IP (handles proxies)
 */
const getClientIP = (req) => {
    return req.ip ||
        req.connection?.remoteAddress ||
        'unknown';
};

// ============================================
// ERROR TRANSFORMERS
// Convert known error types to AppError
// ============================================

const handleCastError = (err) => {
    // Don't expose field names in production
    return new AppError('Invalid identifier format', 400, 'CAST_ERROR');
};

const handleDuplicateKeyError = (err) => {
    // Don't expose which field is duplicated
    return new AppError('Duplicate entry', 409, 'DUPLICATE_KEY');
};

const handleValidationError = (err) => {
    // Don't expose validation details
    return new AppError('Validation failed', 400, 'VALIDATION_ERROR');
};

const handleJWTError = () => {
    return new AppError('Session invalid', 401, 'INVALID_TOKEN');
};

const handleJWTExpiredError = () => {
    return new AppError('Session expired', 401, 'TOKEN_EXPIRED');
};

const handleSyntaxError = () => {
    return new AppError('Invalid request format', 400, 'SYNTAX_ERROR');
};

const handlePayloadTooLargeError = () => {
    return new AppError('Request too large', 413, 'PAYLOAD_TOO_LARGE');
};

// ============================================
// GET SAFE RESPONSE FOR CLIENT
// ============================================

/**
 * SECURITY HARDENED: Get safe response for client
 * 
 * This function ALWAYS returns production-safe messages, regardless of NODE_ENV.
 * Stack traces and internal error details are NEVER sent to clients.
 * 
 * SECURITY FIX: Even if NODE_ENV is accidentally misconfigured or set to 'development'
 * in production, no sensitive information will leak to clients.
 */
const getSafeResponse = (err, requestId, isProduction) => {
    const statusCode = err.statusCode || 500;

    // ============================================
    // SECURITY FIX: ALWAYS return generic messages
    // Never expose internal error details or stack traces
    // This protects against NODE_ENV misconfiguration
    // ============================================

    // For operational errors with safe messages, we can use them
    // But we still sanitize to ensure nothing sensitive slips through
    if (err.isOperational && err.message) {
        // List of patterns that might indicate internal information
        const dangerousPatterns = [
            /at .+\(.+:\d+:\d+\)/, // Stack trace lines
            /\/[a-zA-Z]:?\/.+\.js/,  // File paths
            /node_modules/,          // Node internals
            /Error:/,                // Raw error messages
            /ENOENT|EACCES|ENOMEM/,  // System errors
            /MongoServerError/,      // Database errors
            /Cast to ObjectId/,      // Mongoose errors
            /duplicate key/i,        // DB constraint errors
            /validation failed/i,    // Mongoose validation
        ];

        // Check if message contains any dangerous patterns
        const isSafe = !dangerousPatterns.some(pattern => pattern.test(err.message));

        if (isSafe && err.message.length < 200) {
            return {
                success: false,
                message: err.message,
                code: err.code || 'ERROR',
                requestId,
            };
        }
    }

    // PRODUCTION SAFE: Return only generic message based on status code
    return {
        success: false,
        message: PRODUCTION_MESSAGES[statusCode] || 'An error occurred',
        requestId, // Allow client to reference for support
        // ============================================
        // SECURITY: Never include any of the following in client responses:
        // - Stack traces
        // - Internal error codes beyond safe ones
        // - File paths
        // - Database error details
        // ============================================
    };
};

// ============================================
// GLOBAL ERROR HANDLER MIDDLEWARE
// ============================================

export const globalErrorHandler = (err, req, res, next) => {
    // Ensure we have a request ID
    const requestId = req.requestId || crypto.randomBytes(8).toString('hex');

    // Default to 500 if no status code
    err.statusCode = err.statusCode || 500;

    // Always log full error details server-side
    logError(err, req);

    const isProduction = process.env.NODE_ENV === 'production';

    // Transform known error types
    let error = err;

    // Mongoose CastError (invalid ObjectId)
    if (err.name === 'CastError') {
        error = handleCastError(err);
    }

    // Mongoose Duplicate Key Error
    if (err.code === 11000) {
        error = handleDuplicateKeyError(err);
    }

    // Mongoose Validation Error
    if (err.name === 'ValidationError') {
        error = handleValidationError(err);
    }

    // JWT Errors
    if (err.name === 'JsonWebTokenError') {
        error = handleJWTError();
    }

    if (err.name === 'TokenExpiredError') {
        error = handleJWTExpiredError();
    }

    // JSON Syntax Error (malformed request body)
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        error = handleSyntaxError();
    }

    // Payload too large
    if (err.type === 'entity.too.large') {
        error = handlePayloadTooLargeError();
    }

    // Rate limit error (from express-rate-limit)
    if (err.statusCode === 429) {
        error.isOperational = true;
        error.code = 'RATE_LIMITED';
    }

    // Get safe response for client
    const response = getSafeResponse(error, requestId, isProduction);

    // Set security headers on error responses
    res.setHeader('X-Request-ID', requestId);
    res.setHeader('X-Content-Type-Options', 'nosniff');

    res.status(error.statusCode || 500).json(response);
};

// ============================================
// ASYNC ERROR WRAPPER
// ============================================

export const catchAsync = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

// ============================================
// 404 HANDLER
// ============================================

export const notFoundHandler = (req, res, next) => {
    const requestId = req.requestId || crypto.randomBytes(8).toString('hex');

    // Log 404s as they might indicate scanning attempts
    console.warn(`[404] ${new Date().toISOString()} | ${req.method} ${req.originalUrl} | IP: ${getClientIP(req)} | Request ID: ${requestId}`);

    const err = new AppError('Resource not found', 404, 'NOT_FOUND');
    next(err);
};

// ============================================
// ERROR HELPER
// ============================================

export const throwError = (message, statusCode = 500, code = 'ERROR') => {
    throw new AppError(message, statusCode, code);
};

// ============================================
// UNHANDLED REJECTION & EXCEPTION HANDLERS
// ============================================

process.on('uncaughtException', (err) => {
    console.error('\n' + '🔴'.repeat(30));
    console.error('UNCAUGHT EXCEPTION! Shutting down...');
    console.error('Error:', err.name, err.message);
    console.error('Stack:', err.stack);
    console.error('🔴'.repeat(30) + '\n');
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('\n' + '🟠'.repeat(30));
    console.error('UNHANDLED REJECTION! at:', promise);
    console.error('Reason:', reason);
    console.error('🟠'.repeat(30) + '\n');
    // Don't exit - let the app handle it gracefully
});

export default globalErrorHandler;
