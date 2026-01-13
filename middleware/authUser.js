/**
 * User Authentication Middleware
 * Enterprise-grade security with HttpOnly cookies and server-side session validation
 */
import jwt from "jsonwebtoken";
import User from "../models/userModel.js";
import UserSession from "../models/UserSession.js";

// Cookie configuration
const COOKIE_CONFIG = {
  name: "user_session",
  options: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: "/",
    domain: process.env.COOKIE_DOMAIN || undefined,
  },
};

/**
 * Set session cookie
 */
export const setSessionCookie = (res, sessionToken) => {
  res.cookie(COOKIE_CONFIG.name, sessionToken, COOKIE_CONFIG.options);
};

/**
 * Clear session cookie
 */
export const clearSessionCookie = (res) => {
  res.clearCookie(COOKIE_CONFIG.name, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
    path: "/",
    domain: process.env.COOKIE_DOMAIN || undefined,
  });
};

/**
 * Extract and validate session from HttpOnly cookie
 * Primary authentication method - uses server-side session storage
 * 
 * SECURITY: Cookie authentication is ALWAYS prioritized.
 * If a valid cookie exists, Bearer tokens are IGNORED to prevent
 * token injection attacks.
 */
export const authMiddleware = async (req, res, next) => {
  try {
    // 1. Get session token from HttpOnly cookie (PRIORITY)
    const sessionToken = req.cookies?.[COOKIE_CONFIG.name];

    // ============================================
    // SECURITY FIX: Cookie Priority Over Bearer Token
    // If no cookie exists, fall back to Authorization header
    // This prevents token injection attacks where an attacker
    // forces a browser to use a stolen bearer token while
    // a valid cookie session exists
    // ============================================
    if (!sessionToken) {
      // Only use Authorization header when NO cookie is present
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith("Bearer ")) {
        console.log('[Auth] No cookie, using Bearer token fallback');
        return handleJWTAuth(req, res, next, authHeader.split(" ")[1]);
      }

      console.log('[Auth] No session cookie found');
      return res.status(401).json({
        success: false,
        message: "Authentication required. Please login.",
        code: "NO_SESSION",
      });
    }

    // SECURITY: If cookie exists, we NEVER check Authorization header
    // This prevents attackers from injecting a malicious Bearer token

    // 2. Validate session against database
    const session = await UserSession.validateSession(sessionToken, req);

    if (!session) {
      console.log('[Auth] Session validation failed');
      clearSessionCookie(res);
      return res.status(401).json({
        success: false,
        message: "Session expired or invalid. Please login again.",
        code: "INVALID_SESSION",
      });
    }

    // 3. Get user from session
    const user = session.user;

    if (!user) {
      await UserSession.revokeSession(session._id, "user_not_found");
      clearSessionCookie(res);
      return res.status(401).json({
        success: false,
        message: "User not found. Account may have been deleted.",
        code: "USER_NOT_FOUND",
      });
    }

    // 4. Check if user is blocked
    if (user.isBlocked) {
      await UserSession.revokeSession(session._id, "user_blocked");
      clearSessionCookie(res);
      return res.status(403).json({
        success: false,
        message: "Your account has been blocked. Contact support.",
        code: "ACCOUNT_BLOCKED",
      });
    }

    // 5. Check if user is active
    if (user.isActive === false) {
      await UserSession.revokeSession(session._id, "user_deactivated");
      clearSessionCookie(res);
      return res.status(403).json({
        success: false,
        message: "Your account has been deactivated. Contact support.",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    // 6. Attach user and session to request (sanitized)
    req.user = sanitizeUser(user);
    req.userSession = session;

    next();
  } catch (err) {
    console.error("User auth error:", err);

    // Handle specific security errors
    if (err.message === 'INVALID_USER_ROLE') {
      clearSessionCookie(res);
      return res.status(403).json({
        success: false,
        message: "Your account configuration is invalid. Please contact support.",
        code: "INVALID_ROLE",
      });
    }

    return res.status(401).json({
      success: false,
      message: "Authentication failed. Please login again.",
      code: "AUTH_ERROR",
    });
  }
};

/**
 * Handle JWT-based authentication (fallback for API clients)
 * 
 * SECURITY FIX: Now validates tokens against UserSession store
 * to ensure revoked sessions (logout/ban) are rejected
 */
const handleJWTAuth = async (req, res, next, token) => {
  try {
    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        clearSessionCookie(res);
        return res.status(401).json({
          success: false,
          message: "Session expired. Please login again.",
          code: "TOKEN_EXPIRED",
        });
      }
      if (err.name === "JsonWebTokenError") {
        clearSessionCookie(res);
        return res.status(401).json({
          success: false,
          message: "Invalid token. Please login again.",
          code: "INVALID_TOKEN",
        });
      }
      throw err;
    }

    // ============================================
    // SECURITY FIX: Validate token against UserSession store
    // This ensures:
    // 1. Logged out tokens are rejected
    // 2. Banned users' tokens are rejected
    // 3. Password-changed tokens are rejected
    // ============================================

    // Check if there's an active session for this token
    // The sessionId should be embedded in the JWT payload
    if (decoded.sessionId) {
      const session = await UserSession.findOne({
        _id: decoded.sessionId,
        isRevoked: { $ne: true },
        expiresAt: { $gt: new Date() }
      }).populate('user');

      if (!session) {
        console.warn('[Auth] JWT references revoked/expired session');
        return res.status(401).json({
          success: false,
          message: "Session has been revoked. Please login again.",
          code: "SESSION_REVOKED",
        });
      }

      // Use user from session
      const user = session.user;
      if (!user) {
        return res.status(401).json({
          success: false,
          message: "User not found. Account may have been deleted.",
          code: "USER_NOT_FOUND",
        });
      }

      // Check if user is blocked
      if (user.isBlocked) {
        // Revoke the session
        await UserSession.revokeSession(session._id, "user_blocked");
        return res.status(403).json({
          success: false,
          message: "Your account has been blocked. Contact support.",
          code: "ACCOUNT_BLOCKED",
        });
      }

      // Check if user is active
      if (user.isActive === false) {
        await UserSession.revokeSession(session._id, "user_deactivated");
        return res.status(403).json({
          success: false,
          message: "Your account has been deactivated. Contact support.",
          code: "ACCOUNT_DEACTIVATED",
        });
      }

      // Attach user to request (sanitized)
      req.user = sanitizeUser(user);
      req.userSession = session;
      return next();
    }

    // ============================================
    // LEGACY FALLBACK: For older tokens without sessionId
    // Still validate user status but log warning
    // ============================================
    console.warn('[Auth] Legacy JWT without sessionId detected - consider re-login');

    // Get user from database with security fields
    const user = await User.findById(decoded.id).select(User.getSafeFields());

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found. Account may have been deleted.",
        code: "USER_NOT_FOUND",
      });
    }

    // Check if user is blocked
    if (user.isBlocked) {
      return res.status(403).json({
        success: false,
        message: "Your account has been blocked. Contact support.",
        code: "ACCOUNT_BLOCKED",
      });
    }

    // Check if user is active
    if (user.isActive === false) {
      return res.status(403).json({
        success: false,
        message: "Your account has been deactivated. Contact support.",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    // Check if password changed after token issued
    if (user.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({
        success: false,
        message: "Password was recently changed. Please login again.",
        code: "PASSWORD_CHANGED",
      });
    }

    // Attach user to request (sanitized)
    req.user = sanitizeUser(user);

    next();
  } catch (err) {
    console.error("JWT auth error:", err);
    return res.status(401).json({
      success: false,
      message: "Authentication failed. Please login again.",
      code: "AUTH_ERROR",
    });
  }
};

/**
 * Sanitize user object - remove all sensitive fields
 * 
 * SECURITY FIX: No longer defaults missing roles to 'buyer'.
 * If a user lacks a valid role, this function throws an error.
 * This prevents implicit privilege grants via malformed user records.
 */
const sanitizeUser = (user) => {
  const userObj = user.toObject ? user.toObject() : { ...user };

  // ============================================
  // SECURITY FIX: Reject users without valid roles
  // Do NOT default to 'buyer' - this could grant unintended access
  // ============================================
  const VALID_ROLES = ['user', 'buyer', 'owner'];
  if (!userObj.role || !VALID_ROLES.includes(userObj.role)) {
    console.error(`[Auth] SECURITY: User ${userObj.email || userObj._id} has invalid/missing role: ${userObj.role || 'undefined'}`);
    throw new Error('INVALID_USER_ROLE');
  }

  // Remove sensitive fields
  const sensitiveFields = [
    "password",
    "otp",
    "otpExpires",
    "resetPasswordOtp",
    "resetPasswordOtpExpires",
    "blockReason",
    "blockedAt",
    "blockedBy",
    "__v",
  ];

  sensitiveFields.forEach((field) => delete userObj[field]);

  // Remove internal security fields
  if (userObj.security) {
    delete userObj.security.failedLoginAttempts;
    delete userObj.security.lockoutUntil;
    delete userObj.security.lastLoginIp;
  }

  return userObj;
};

/**
 * Optional authentication - proceeds even without token
 * Useful for routes that work for both authenticated and anonymous users
 */
export const optionalAuth = async (req, res, next) => {
  const sessionToken = req.cookies?.[COOKIE_CONFIG.name];
  const authHeader = req.headers.authorization;

  if (!sessionToken && (!authHeader || !authHeader.startsWith("Bearer "))) {
    req.user = null;
    return next();
  }

  try {
    if (sessionToken) {
      // Cookie-based session
      const session = await UserSession.validateSession(sessionToken, req);
      if (session && session.user && !session.user.isBlocked && session.user.isActive !== false) {
        req.user = sanitizeUser(session.user);
        req.userSession = session;
      } else {
        req.user = null;
      }
    } else if (authHeader?.startsWith("Bearer ")) {
      // JWT fallback
      const token = authHeader.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id).select(User.getSafeFields());

      if (user && !user.isBlocked && user.isActive !== false && !user.changedPasswordAfter(decoded.iat)) {
        req.user = sanitizeUser(user);
      } else {
        req.user = null;
      }
    }
  } catch (err) {
    // Token is invalid but we proceed anyway for optional auth
    req.user = null;
  }

  next();
};

/**
 * Role-based access control middleware
 * Usage: requireRole("owner", "admin")
 */
export const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
        code: "NOT_AUTHENTICATED",
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: "You do not have permission to access this resource.",
        code: "FORBIDDEN",
        requiredRoles: allowedRoles,
      });
    }

    next();
  };
};

/**
 * Verify user owns the resource or is admin
 */
export const requireOwnership = (getResourceOwnerId) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
        code: "NOT_AUTHENTICATED",
      });
    }

    // Owners can access their own resources
    try {
      const ownerId = await getResourceOwnerId(req);

      if (!ownerId) {
        return res.status(404).json({
          success: false,
          message: "Resource not found.",
          code: "NOT_FOUND",
        });
      }

      if (ownerId.toString() !== req.user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: "You do not have permission to access this resource.",
          code: "NOT_OWNER",
        });
      }

      next();
    } catch (err) {
      console.error("Ownership check error:", err);
      return res.status(500).json({
        success: false,
        message: "Authorization check failed.",
        code: "OWNERSHIP_CHECK_ERROR",
      });
    }
  };
};

/**
 * Require verified email
 */
export const requireVerified = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: "Authentication required.",
      code: "NOT_AUTHENTICATED",
    });
  }

  if (!req.user.isVerified) {
    return res.status(403).json({
      success: false,
      message: "Email verification required.",
      code: "EMAIL_NOT_VERIFIED",
    });
  }

  next();
};

/**
 * Rate limiting for auth endpoints
 */
const authAttempts = new Map();

export const authRateLimit = (req, res, next) => {
  const ip = req.ip || req.connection?.remoteAddress || "unknown";
  const key = `auth:${ip}`;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxAttempts = 10;

  const attempts = authAttempts.get(key) || { count: 0, resetAt: now + windowMs };

  if (now > attempts.resetAt) {
    attempts.count = 0;
    attempts.resetAt = now + windowMs;
  }

  attempts.count++;
  authAttempts.set(key, attempts);

  // Cleanup old entries periodically
  if (authAttempts.size > 10000) {
    for (const [k, v] of authAttempts.entries()) {
      if (now > v.resetAt) authAttempts.delete(k);
    }
  }

  if (attempts.count > maxAttempts) {
    return res.status(429).json({
      success: false,
      message: "Too many attempts. Please try again later.",
      code: "RATE_LIMITED",
      retryAfter: Math.ceil((attempts.resetAt - now) / 1000),
    });
  }

  next();
};

// Export cookie config for use in controllers
export { COOKIE_CONFIG };
