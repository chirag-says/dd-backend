import Admin from "../models/Admin.js";
import AdminSession from "../models/AdminSession.js";
import AuditLog from "../models/AuditLog.js";

/**
 * Cookie configuration for secure session management
 */
export const COOKIE_CONFIG = {
  name: "admin_session",
  options: {
    httpOnly: true, // Prevents XSS attacks - cookie not accessible via JavaScript
    secure: process.env.NODE_ENV === "production", // HTTPS only in production
    sameSite: "strict", // Prevents CSRF attacks
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: "/",
    domain: process.env.COOKIE_DOMAIN || undefined,
  },
};

/**
 * MFA cookie configuration (shorter lived)
 */
export const MFA_COOKIE_CONFIG = {
  name: "admin_mfa_pending",
  options: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 10 * 60 * 1000, // 10 minutes to complete MFA
    path: "/",
  },
};

/**
 * Extract client IP address from request
 * SECURITY: Prioritize req.ip (verified by Express trust proxy setting)
 * over raw x-forwarded-for to prevent IP spoofing for rate limit bypass
 */
const getClientIp = (req) => {
  // req.ip is verified against trust proxy configuration in server.js
  // This prevents attackers from spoofing IPs via x-forwarded-for
  return (
    req.ip ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    "unknown"
  );
};

/**
 * Parse user agent for device info
 */
const parseUserAgent = (userAgent = "") => {
  const info = {
    browser: "Unknown",
    os: "Unknown",
    device: "Unknown",
  };

  // Simple parsing - in production, use a proper UA parser library
  if (userAgent.includes("Chrome")) info.browser = "Chrome";
  else if (userAgent.includes("Firefox")) info.browser = "Firefox";
  else if (userAgent.includes("Safari")) info.browser = "Safari";
  else if (userAgent.includes("Edge")) info.browser = "Edge";

  if (userAgent.includes("Windows")) info.os = "Windows";
  else if (userAgent.includes("Mac")) info.os = "macOS";
  else if (userAgent.includes("Linux")) info.os = "Linux";
  else if (userAgent.includes("Android")) info.os = "Android";
  else if (userAgent.includes("iOS")) info.os = "iOS";

  if (userAgent.includes("Mobile")) info.device = "Mobile";
  else if (userAgent.includes("Tablet")) info.device = "Tablet";
  else info.device = "Desktop";

  return info;
};

/**
 * Create a new admin session
 * 
 * SECURITY FIX: mfaVerified is NEVER auto-set to true.
 * All admin sessions must complete MFA verification explicitly.
 */
export const createSession = async (admin, req) => {
  const sessionToken = AdminSession.generateToken();
  const fingerprint = AdminSession.generateFingerprint(req);
  const clientIp = getClientIp(req);
  const userAgent = req.headers["user-agent"] || "";
  const deviceInfo = parseUserAgent(userAgent);

  // ============================================
  // SECURITY FIX: mfaVerified is ALWAYS false at session creation.
  // Every admin MUST complete MFA verification regardless of role type.
  // This prevents bypass attacks via legacy admin detection.
  // ============================================
  const session = await AdminSession.create({
    admin: admin._id,
    sessionToken,
    fingerprint,
    ipAddress: clientIp,
    userAgent,
    deviceInfo,
    expiresAt: new Date(Date.now() + COOKIE_CONFIG.options.maxAge),
    mfaVerified: false, // SECURITY: Always false - MFA must be verified explicitly
  });

  return { session, sessionToken };
};

/**
 * Set session cookie on response
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
    sameSite: "strict",
    path: "/",
  });
};

/**
 * Set MFA pending cookie
 */
export const setMfaPendingCookie = (res, sessionToken) => {
  res.cookie(MFA_COOKIE_CONFIG.name, sessionToken, MFA_COOKIE_CONFIG.options);
};

/**
 * Clear MFA pending cookie
 */
export const clearMfaPendingCookie = (res) => {
  res.clearCookie(MFA_COOKIE_CONFIG.name, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
  });
};

/**
 * Main admin protection middleware
 * Strictly verifies session integrity against the database
 * Supports both HttpOnly cookies (preferred) and Bearer tokens (fallback for migration)
 * 
 * SECURITY FIXES:
 * - Removed all legacy admin bypass logic
 * - MFA is now required for ALL admin sessions
 * - No auto-setting of mfaVerified to true
 */
export const protectAdmin = async (req, res, next) => {
  const startTime = Date.now();

  try {
    // Extract session token from HttpOnly cookie (preferred)
    let sessionToken = req.cookies?.[COOKIE_CONFIG.name];

    // Fallback: Check Authorization header for Bearer token (backward compatibility)
    if (!sessionToken) {
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith("Bearer ")) {
        sessionToken = authHeader.split(" ")[1];
      }
    }

    if (!sessionToken) {
      await AuditLog.log({
        admin: null,
        category: "authentication",
        action: "access_denied",
        description: "No session token provided",
        req,
        result: "denied",
        severity: "medium",
        isSecurityEvent: true,
      });

      return res.status(401).json({
        success: false,
        message: "Authentication required. Please log in.",
        code: "NO_SESSION",
      });
    }

    // Find and validate session in database
    const session = await AdminSession.findOne({
      sessionToken,
      isActive: true,
      expiresAt: { $gt: new Date() },
    });

    if (!session) {
      clearSessionCookie(res);

      await AuditLog.log({
        admin: null,
        category: "authentication",
        action: "invalid_session",
        description: "Session token not found or expired",
        req,
        result: "denied",
        severity: "medium",
        isSecurityEvent: true,
      });

      return res.status(401).json({
        success: false,
        message: "Session expired or invalid. Please log in again.",
        code: "INVALID_SESSION",
      });
    }

    // ============================================
    // SECURITY FIX: STRICT session fingerprint validation
    // Rejects ANY User-Agent or IP address change immediately
    // This prevents session hijacking via stolen tokens
    // ============================================
    const fingerprintValidation = session.validateFingerprintStrict(req);
    if (!fingerprintValidation.valid) {
      // Session hijacking attempt detected - revoke immediately
      await session.revoke(`strict_fingerprint_mismatch: ${fingerprintValidation.reason}`);
      clearSessionCookie(res);

      await AuditLog.log({
        admin: session.admin,
        category: "authentication",
        action: "session_revoked_strict_fingerprint",
        description: `Session revoked: ${fingerprintValidation.reason}`,
        req,
        result: "denied",
        severity: "critical",
        isSecurityEvent: true,
      });

      return res.status(401).json({
        success: false,
        message: "Session verification failed. Please log in again.",
        code: "SESSION_FINGERPRINT_MISMATCH",
      });
    }

    // ============================================
    // SECURITY FIX: MFA is ALWAYS required for ALL admin sessions
    // 
    // Special case: mfaSetupPending = true means admin needs to set up MFA
    // In this case, ONLY allow access to MFA setup endpoints (/mfa/setup, /mfa/verify-setup)
    // ============================================
    console.log("[AUTH] Session mfaVerified:", session.mfaVerified, "mfaSetupPending:", session.mfaSetupPending);

    if (!session.mfaVerified) {
      // Check if this is an MFA setup pending session
      if (session.mfaSetupPending) {
        // Allow ONLY MFA setup endpoints
        const allowedPaths = ['/mfa/setup', '/mfa/verify-setup', '/mfa/generate-secret', '/mfa/confirm'];
        const isAllowedPath = allowedPaths.some(path => req.path.includes(path));

        if (!isAllowedPath) {
          console.log("[AUTH] MFA setup pending - blocking access to:", req.path);
          return res.status(403).json({
            success: false,
            message: "MFA setup is required before accessing admin features.",
            code: "MFA_SETUP_REQUIRED",
            requiresMfaSetup: true,
            mfaSetupPending: true,
          });
        }

        // Allow access to MFA setup endpoints
        console.log("[AUTH] MFA setup pending - allowing access to:", req.path);
      } else {
        // Regular MFA verification required
        console.log("[AUTH] MFA not verified - requiring MFA for all admin sessions");
        return res.status(403).json({
          success: false,
          message: "Multi-factor authentication required.",
          code: "MFA_REQUIRED",
          requiresMfa: true,
        });
      }
    }

    // Get admin from database
    // Note: Don't populate role - legacy admins have string roles instead of ObjectIds
    const admin = await Admin.findById(session.admin);

    if (!admin) {
      await session.revoke("admin_not_found");
      clearSessionCookie(res);

      return res.status(401).json({
        success: false,
        message: "Admin account not found.",
        code: "ADMIN_NOT_FOUND",
      });
    }

    // Check if admin account is active (default to true for legacy admins)
    if (admin.isActive === false) {
      await session.revoke("admin_deactivated");
      clearSessionCookie(res);

      await AuditLog.log({
        admin: admin._id,
        category: "authentication",
        action: "access_denied_inactive",
        description: "Inactive admin attempted to access protected resource",
        req,
        result: "denied",
        severity: "high",
        isSecurityEvent: true,
      });

      return res.status(403).json({
        success: false,
        message: "Your account has been deactivated. Contact a super admin.",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    // Check if admin is locked out
    if (admin.isLocked) {
      const lockExpiry = admin.security.lockoutUntil;
      const remainingMinutes = Math.ceil((lockExpiry - Date.now()) / 60000);

      return res.status(403).json({
        success: false,
        message: `Account temporarily locked. Try again in ${remainingMinutes} minutes.`,
        code: "ACCOUNT_LOCKED",
        lockoutUntil: lockExpiry,
      });
    }

    // Check if password must be changed
    if (admin.security.mustChangePassword) {
      // Only allow password change endpoint OR MFA setup endpoints
      const isMfaEndpoint = ['/mfa/setup', '/mfa/verify-setup', '/mfa/generate-secret', '/mfa/confirm'].some(path => req.originalUrl.includes(path));

      if (!req.originalUrl.includes("/change-password") && !isMfaEndpoint) {
        return res.status(403).json({
          success: false,
          message: "You must change your password before continuing.",
          code: "PASSWORD_CHANGE_REQUIRED",
          requiresPasswordChange: true,
        });
      }
    }

    // Update session last activity
    await session.touch();

    // Attach admin and session to request
    req.admin = admin;
    req.adminSession = session;
    req.clientIp = getClientIp(req);

    // Calculate request duration for audit
    res.on("finish", async () => {
      const duration = Date.now() - startTime;

      // Log successful access (for sensitive operations)
      if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
        await AuditLog.log({
          admin: admin._id,
          category: "data_access",
          action: `${req.method.toLowerCase()}_request`,
          description: `${req.method} ${req.originalUrl}`,
          req,
          sessionId: session._id,
          result: res.statusCode < 400 ? "success" : "failure",
          statusCode: res.statusCode,
          duration,
        });
      }
    });

    next();
  } catch (error) {
    console.error("Admin auth middleware error:", error);

    // Clear potentially invalid session cookie
    clearSessionCookie(res);

    await AuditLog.log({
      admin: null,
      category: "system",
      action: "auth_middleware_error",
      description: "Unexpected error in admin authentication middleware",
      req,
      result: "failure",
      error,
      severity: "high",
    });

    return res.status(500).json({
      success: false,
      message: "Authentication error. Please try again.",
      code: "AUTH_ERROR",
    });
  }
};

/**
 * Permission checking middleware factory
 * Use: requirePermission("users:read")
 */
export const requirePermission = (...requiredPermissions) => {
  return async (req, res, next) => {
    try {
      if (!req.admin) {
        return res.status(401).json({
          success: false,
          message: "Authentication required.",
          code: "NOT_AUTHENTICATED",
        });
      }

      // Get admin's permission codes
      const adminPermissions = await req.admin.getPermissions();

      // Check if admin has any of the required permissions
      const hasPermission = requiredPermissions.some((perm) => adminPermissions.includes(perm));

      if (!hasPermission) {
        await AuditLog.log({
          admin: req.admin._id,
          category: "authorization",
          action: "permission_denied",
          description: `Access denied. Required: [${requiredPermissions.join(", ")}]`,
          req,
          sessionId: req.adminSession?._id,
          result: "denied",
          severity: "medium",
          metadata: { requiredPermissions, adminPermissions },
        });

        return res.status(403).json({
          success: false,
          message: "You do not have permission to perform this action.",
          code: "PERMISSION_DENIED",
          required: requiredPermissions,
        });
      }

      next();
    } catch (error) {
      console.error("Permission check error:", error);
      return res.status(500).json({
        success: false,
        message: "Authorization error.",
        code: "AUTHORIZATION_ERROR",
      });
    }
  };
};

/**
 * Role level checking middleware factory
 * Use: requireRoleLevel(50) // Requires role with level >= 50
 */
export const requireRoleLevel = (minLevel) => {
  return async (req, res, next) => {
    try {
      if (!req.admin) {
        return res.status(401).json({
          success: false,
          message: "Authentication required.",
          code: "NOT_AUTHENTICATED",
        });
      }

      const roleLevel = req.admin.role?.level || 0;

      if (roleLevel < minLevel) {
        await AuditLog.log({
          admin: req.admin._id,
          category: "authorization",
          action: "role_level_denied",
          description: `Access denied. Required level: ${minLevel}, Admin level: ${roleLevel}`,
          req,
          sessionId: req.adminSession?._id,
          result: "denied",
          severity: "medium",
        });

        return res.status(403).json({
          success: false,
          message: "Insufficient privileges for this action.",
          code: "INSUFFICIENT_ROLE_LEVEL",
        });
      }

      next();
    } catch (error) {
      console.error("Role level check error:", error);
      return res.status(500).json({
        success: false,
        message: "Authorization error.",
        code: "AUTHORIZATION_ERROR",
      });
    }
  };
};

/**
 * Super admin only middleware
 */
export const requireSuperAdmin = requireRoleLevel(100);

/**
 * Rate limiting for authentication endpoints
 */
const authAttempts = new Map();

export const authRateLimit = (req, res, next) => {
  const clientIp = getClientIp(req);
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxAttempts = 10;

  // Clean up old entries
  for (const [ip, data] of authAttempts.entries()) {
    if (now - data.firstAttempt > windowMs) {
      authAttempts.delete(ip);
    }
  }

  const attempts = authAttempts.get(clientIp);

  if (attempts) {
    if (attempts.count >= maxAttempts && now - attempts.firstAttempt < windowMs) {
      const retryAfter = Math.ceil((attempts.firstAttempt + windowMs - now) / 1000);

      return res.status(429).json({
        success: false,
        message: "Too many authentication attempts. Please try again later.",
        code: "RATE_LIMITED",
        retryAfter,
      });
    }

    attempts.count++;
  } else {
    authAttempts.set(clientIp, { count: 1, firstAttempt: now });
  }

  next();
};

/**
 * Clear rate limit on successful auth
 */
export const clearAuthRateLimit = (req) => {
  const clientIp = getClientIp(req);
  authAttempts.delete(clientIp);
};
