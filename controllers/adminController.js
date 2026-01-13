import bcrypt from "bcryptjs";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import Admin from "../models/Admin.js";
import AdminSession from "../models/AdminSession.js";
import AuditLog from "../models/AuditLog.js";
import Role from "../models/Role.js";
import User from "../models/userModel.js";
import Property from "../models/Property.js";
import Lead from "../models/Lead.js";
import Report from "../models/Report.js";
import {
  createSession,
  setSessionCookie,
  clearSessionCookie,
  setMfaPendingCookie,
  clearMfaPendingCookie,
  clearAuthRateLimit,
  MFA_COOKIE_CONFIG,
} from "../middleware/authAdmin.js";

/**
 * Helper: Get client IP from request
 */
const getClientIp = (req) => {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.connection?.remoteAddress ||
    req.ip ||
    "unknown"
  );
};

/**
 * Register Admin
 * Only super_admins can create new admins
 */
export const registerAdmin = async (req, res) => {
  const startTime = Date.now();

  try {
    const { name, email, password, roleId } = req.body;

    // Validate required fields
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email, and password are required",
      });
    }

    // ============================================
    // SECURITY FIX: Strong password validation for admins
    // Admins require stronger passwords (12+ chars) than regular users
    // ============================================
    const ADMIN_PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()\-_=+])[A-Za-z\d@$!%*?&#^()\-_=+]{12,}$/;

    if (!ADMIN_PASSWORD_REGEX.test(password)) {
      return res.status(400).json({
        success: false,
        message: "Admin password must be at least 12 characters and include uppercase, lowercase, number, and special character (@$!%*?&#^()-_=+)",
      });
    }

    // Check if admin already exists
    // SECURITY FIX: Don't reveal if email exists (prevents enumeration attacks)
    const existingAdmin = await Admin.findOne({ email: email.toLowerCase() });
    if (existingAdmin) {
      // Log the attempt for security monitoring
      await AuditLog.log({
        admin: req.admin?._id || null,
        category: "security",
        action: "admin_registration_duplicate_attempt",
        description: `Registration attempted with existing email`,
        req,
        result: "denied",
        severity: "medium",
        isSecurityEvent: true,
      });

      // Return generic message to prevent email enumeration
      return res.status(400).json({
        success: false,
        message: "Unable to complete registration. Please contact a super admin.",
      });
    }

    // Get role (default to lowest privilege role if not specified)
    let role;
    if (roleId) {
      role = await Role.findById(roleId);
      if (!role) {
        return res.status(400).json({
          success: false,
          message: "Invalid role specified",
        });
      }
    } else {
      // Find the default viewer role
      role = await Role.findOne({ name: "viewer" });
      if (!role) {
        // Create default roles if they don't exist
        role = await createDefaultRoles();
      }
    }

    // Check if registering admin has permission to assign this role
    if (req.admin) {
      const creatorRole = await Role.findById(req.admin.role);
      if (creatorRole && role.level >= creatorRole.level) {
        return res.status(403).json({
          success: false,
          message: "You cannot create an admin with equal or higher privileges",
        });
      }
    }

    // Create new admin
    const newAdmin = await Admin.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password,
      role: role._id,
      createdBy: req.admin?._id || null,
      mfa: {
        enabled: false,
        required: true, // MFA setup will be required on first login
      },
      security: {
        mustChangePassword: true, // Must change password on first login
      },
    });

    // Log the action
    await AuditLog.log({
      admin: req.admin?._id || newAdmin._id,
      category: "admin_management",
      action: "admin_created",
      resourceType: "admin",
      resourceId: newAdmin._id,
      description: `New admin created: ${newAdmin.email}`,
      req,
      result: "success",
      duration: Date.now() - startTime,
    });

    res.status(201).json({
      success: true,
      message: "Admin registered successfully. MFA setup required on first login.",
      admin: {
        _id: newAdmin._id,
        name: newAdmin.name,
        email: newAdmin.email,
        role: role.displayName,
        requiresMfaSetup: true,
        mustChangePassword: true,
      },
    });
  } catch (error) {
    console.error("Register admin error:", error);

    await AuditLog.log({
      admin: req.admin?._id,
      category: "admin_management",
      action: "admin_create_failed",
      description: `Failed to create admin: ${error.message}`,
      req,
      result: "failure",
      error,
      severity: "medium",
    });

    res.status(500).json({
      success: false,
      message: 'An unexpected error occurred' || "Failed to register admin",
    });
  }
};

/**
 * Login Admin
 * Database-only authentication with secure cookie session
 */
export const loginAdmin = async (req, res) => {
  const startTime = Date.now();
  const clientIp = getClientIp(req);

  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Find admin with password field included
    // Note: Don't populate role here - legacy admins may have string roles instead of ObjectIds
    const admin = await Admin.findOne({ email: normalizedEmail })
      .select("+password");

    if (!admin) {
      // Log failed attempt (no user found)
      await AuditLog.logAuth(
        null,
        "login_failed",
        req,
        "failure",
        new Error("Admin not found")
      );

      // Use generic message to prevent user enumeration
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // Check if account is active (default to true for legacy admins)
    if (admin.isActive === false) {
      await AuditLog.logAuth(admin._id, "login_failed_inactive", req, "failure");

      return res.status(403).json({
        success: false,
        message: "Your account has been deactivated. Contact a super admin.",
        code: "ACCOUNT_DEACTIVATED",
      });
    }

    // Check if account is locked
    if (admin.isLocked) {
      const lockExpiry = admin.security.lockoutUntil;
      const remainingMinutes = Math.ceil((lockExpiry - Date.now()) / 60000);

      await AuditLog.logAuth(admin._id, "login_failed_locked", req, "failure");

      return res.status(403).json({
        success: false,
        message: `Account locked due to too many failed attempts. Try again in ${remainingMinutes} minutes.`,
        code: "ACCOUNT_LOCKED",
        lockoutUntil: lockExpiry,
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, admin.password);

    if (!isPasswordValid) {
      // Increment failed attempts
      await admin.incrementLoginAttempts();

      await AuditLog.logAuth(
        admin._id,
        "login_failed",
        req,
        "failure",
        new Error("Invalid password")
      );

      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // Clear rate limit on successful password verification
    clearAuthRateLimit(req);

    // Create session
    const { session, sessionToken } = await createSession(admin, req);

    // Check if MFA is required (handle legacy admins without mfa field)
    const mfaEnabled = admin.mfa?.enabled ?? false;
    const mfaRequired = admin.mfa?.required ?? false;
    const mustChangePassword = admin.security?.mustChangePassword ?? false;

    if (mfaEnabled) {
      // Set MFA pending cookie (short-lived)
      setMfaPendingCookie(res, sessionToken);

      await AuditLog.logAuth(admin._id, "login_mfa_pending", req, "partial");

      return res.status(200).json({
        success: true,
        message: "MFA verification required",
        requiresMfa: true,
        mfaType: "totp",
      });
    }

    // ============================================
    // SECURITY FIX: MFA Setup Race Condition Prevention
    // When MFA is required but not enabled (new admin first login),
    // DO NOT set mfaVerified = true. Instead, issue a special
    // session that can ONLY be used to set up MFA.
    // The protectAdmin middleware will block all other routes.
    // ============================================
    if (mfaRequired && !mfaEnabled) {
      // Session is created with mfaVerified = false (default)
      // Admin can ONLY access: /admin/mfa/setup endpoint
      // All other protected routes will return 403 MFA_REQUIRED

      // Set a special flag to indicate MFA setup is pending
      session.mfaSetupPending = true;
      session.mfaVerified = false; // SECURITY: Explicitly false until setup complete
      await session.save();

      // Set the session cookie (limited access)
      setSessionCookie(res, sessionToken);
      await admin.resetLoginAttempts(clientIp);

      await AuditLog.logAuth(admin._id, "login_success_mfa_setup_required", req, "partial");

      return res.status(200).json({
        success: true,
        message: "Login successful. MFA setup is required before accessing admin features.",
        requiresMfaSetup: true,
        mfaSetupPending: true, // Client should redirect to MFA setup
        mustChangePassword,
        admin: {
          _id: admin._id,
          name: admin.name,
          email: admin.email,
          // Handle both legacy string roles and new ObjectId roles
          role: typeof admin.role === "string" ? admin.role : (admin.role?.displayName || admin.role?.name || "Admin"),
          roleLevel: typeof admin.role === "object" ? (admin.role?.level || 0) : 0,
        },
      });
    }

    // No MFA required - complete login
    session.mfaVerified = true;
    await session.save();

    setSessionCookie(res, sessionToken);
    await admin.resetLoginAttempts(clientIp);

    await AuditLog.logAuth(admin._id, "login_success", req, "success");

    res.status(200).json({
      success: true,
      message: "Login successful",
      mustChangePassword,
      admin: {
        _id: admin._id,
        name: admin.name,
        email: admin.email,
        // Handle both legacy string roles and new ObjectId roles
        role: typeof admin.role === "string" ? admin.role : (admin.role?.displayName || admin.role?.name || "Admin"),
        roleLevel: typeof admin.role === "object" ? (admin.role?.level || 0) : 0,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    console.error("Login error stack:", error.stack);

    // Try to log audit but don't let it fail the error response
    try {
      await AuditLog.log({
        admin: null,
        category: "authentication",
        action: "login_error",
        description: `Login error: ${error.message}`,
        req,
        result: "failure",
        error,
        severity: "high",
      });
    } catch (auditErr) {
      console.error("Audit log error:", auditErr.message);
    }

    res.status(500).json({
      success: false,
      message: "An error occurred during login. Please try again.",
      // Include error details in development
      ...(process.env.NODE_ENV === "development" && { debug: error.message }),
    });
  }
};

/**
 * Verify MFA Code
 */
export const verifyMfa = async (req, res) => {
  try {
    const { code, isBackupCode } = req.body;

    // Get pending MFA session token from cookie
    const pendingToken = req.cookies?.[MFA_COOKIE_CONFIG.name];

    if (!pendingToken) {
      return res.status(401).json({
        success: false,
        message: "MFA session expired. Please login again.",
        code: "MFA_SESSION_EXPIRED",
      });
    }

    // Find the session
    const session = await AdminSession.findOne({
      sessionToken: pendingToken,
      isActive: true,
      mfaVerified: false,
    });

    if (!session) {
      clearMfaPendingCookie(res);
      return res.status(401).json({
        success: false,
        message: "Invalid or expired MFA session.",
        code: "INVALID_MFA_SESSION",
      });
    }

    // Get admin with MFA secret
    const admin = await Admin.findById(session.admin)
      .select("+mfa.secret +mfa.backupCodes")
      .populate("role");

    if (!admin) {
      await session.revoke("admin_not_found");
      clearMfaPendingCookie(res);
      return res.status(401).json({
        success: false,
        message: "Admin not found.",
      });
    }

    let isValid = false;

    if (isBackupCode) {
      // Verify backup code
      isValid = await admin.verifyBackupCode(code);
    } else {
      // Verify TOTP code
      isValid = speakeasy.totp.verify({
        secret: admin.mfa.secret,
        encoding: "base32",
        token: code,
        window: 1, // Allow 1 step tolerance
      });
    }

    if (!isValid) {
      await AuditLog.logAuth(admin._id, "mfa_failed", req, "failure");

      return res.status(401).json({
        success: false,
        message: isBackupCode ? "Invalid backup code" : "Invalid verification code",
      });
    }

    // MFA verified - upgrade session
    session.mfaVerified = true;
    await session.save();

    // Update admin MFA last verified
    admin.mfa.lastVerified = new Date();
    await admin.save();

    // Clear MFA pending cookie and set full session cookie
    clearMfaPendingCookie(res);
    setSessionCookie(res, pendingToken);

    await admin.resetLoginAttempts(getClientIp(req));
    await AuditLog.logAuth(admin._id, "mfa_success", req, "success");

    res.status(200).json({
      success: true,
      message: "MFA verification successful",
      admin: {
        _id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role?.displayName || "Admin",
        roleLevel: admin.role?.level || 0,
      },
    });
  } catch (error) {
    console.error("MFA verification error:", error);
    res.status(500).json({
      success: false,
      message: "MFA verification failed",
    });
  }
};

/**
 * Setup MFA for admin
 */
export const setupMfa = async (req, res) => {
  try {
    const admin = req.admin;

    if (admin.mfa.enabled) {
      return res.status(400).json({
        success: false,
        message: "MFA is already enabled for this account",
      });
    }

    // Generate new secret
    const secret = speakeasy.generateSecret({
      name: `DealDirect Admin (${admin.email})`,
      issuer: "DealDirect",
      length: 32,
    });

    // Generate QR code
    const qrCodeDataUrl = await qrcode.toDataURL(secret.otpauth_url);

    // Generate backup codes
    const backupCodes = admin.generateBackupCodes();
    const hashedBackupCodes = await admin.hashBackupCodes(backupCodes);

    // Store secret and backup codes (not enabled yet until verified)
    admin.mfa.secret = secret.base32;
    admin.mfa.backupCodes = hashedBackupCodes;
    await admin.save();

    await AuditLog.log({
      admin: admin._id,
      category: "security",
      action: "mfa_setup_initiated",
      description: "MFA setup initiated",
      req,
      result: "success",
    });

    res.status(200).json({
      success: true,
      message: "MFA setup initiated. Scan the QR code and verify.",
      qrCode: qrCodeDataUrl,
      manualEntry: secret.base32,
      backupCodes, // Show backup codes only once
    });
  } catch (error) {
    console.error("MFA setup error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to setup MFA",
    });
  }
};

/**
 * Confirm MFA setup with verification code
 */
export const confirmMfaSetup = async (req, res) => {
  try {
    const { code } = req.body;
    const admin = await Admin.findById(req.admin._id).select("+mfa.secret");

    if (!admin.mfa.secret) {
      return res.status(400).json({
        success: false,
        message: "MFA setup not initiated. Please start setup first.",
      });
    }

    // Verify the code
    const isValid = speakeasy.totp.verify({
      secret: admin.mfa.secret,
      encoding: "base32",
      token: code,
      window: 1,
    });

    if (!isValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid verification code. Please try again.",
      });
    }

    // Enable MFA
    admin.mfa.enabled = true;
    admin.mfa.lastVerified = new Date();
    await admin.save();

    // SECURITY FIX: Update current session to reflect verified status
    // otherwise the user remains stuck in "pending setup" loop for this session
    if (req.adminSession) {
      req.adminSession.mfaVerified = true;
      req.adminSession.mfaSetupPending = false;
      await req.adminSession.save();
    }

    await AuditLog.log({
      admin: admin._id,
      category: "security",
      action: "mfa_enabled",
      description: "MFA successfully enabled",
      req,
      result: "success",
      severity: "medium",
    });

    res.status(200).json({
      success: true,
      message: "MFA has been successfully enabled",
    });
  } catch (error) {
    console.error("MFA confirm error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to confirm MFA setup",
    });
  }
};

/**
 * Disable MFA (requires super admin or own account with password)
 */
export const disableMfa = async (req, res) => {
  try {
    const { password, adminId } = req.body;
    const requestingAdmin = req.admin;

    // Determine target admin
    let targetAdmin;
    if (adminId && adminId !== requestingAdmin._id.toString()) {
      // Trying to disable MFA for another admin - requires super admin
      if (requestingAdmin.role?.level < 100) {
        return res.status(403).json({
          success: false,
          message: "Only super admins can disable MFA for other admins",
        });
      }
      targetAdmin = await Admin.findById(adminId);
    } else {
      // Disabling own MFA - requires password
      if (!password) {
        return res.status(400).json({
          success: false,
          message: "Password is required to disable MFA",
        });
      }

      targetAdmin = await Admin.findById(requestingAdmin._id).select("+password");
      const isPasswordValid = await bcrypt.compare(password, targetAdmin.password);

      if (!isPasswordValid) {
        await AuditLog.log({
          admin: requestingAdmin._id,
          category: "security",
          action: "mfa_disable_failed",
          description: "Failed MFA disable attempt - invalid password",
          req,
          result: "failure",
          severity: "high",
          isSecurityEvent: true,
        });

        return res.status(401).json({
          success: false,
          message: "Invalid password",
        });
      }
    }

    if (!targetAdmin) {
      return res.status(404).json({
        success: false,
        message: "Admin not found",
      });
    }

    // Disable MFA
    targetAdmin.mfa.enabled = false;
    targetAdmin.mfa.secret = undefined;
    targetAdmin.mfa.backupCodes = [];
    targetAdmin.mfa.lastVerified = null;
    await targetAdmin.save();

    await AuditLog.log({
      admin: requestingAdmin._id,
      category: "security",
      action: "mfa_disabled",
      resourceType: "admin",
      resourceId: targetAdmin._id,
      description: `MFA disabled for admin: ${targetAdmin.email}`,
      req,
      result: "success",
      severity: "high",
      isSecurityEvent: true,
    });

    res.status(200).json({
      success: true,
      message: "MFA has been disabled",
    });
  } catch (error) {
    console.error("MFA disable error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to disable MFA",
    });
  }
};

/**
 * Logout Admin
 * Revokes server-side session and clears cookie
 */
export const logoutAdmin = async (req, res) => {
  try {
    const session = req.adminSession;

    if (session) {
      await session.revoke("manual_logout");

      await AuditLog.log({
        admin: req.admin?._id,
        category: "authentication",
        action: "logout",
        description: "Admin logged out",
        req,
        sessionId: session._id,
        result: "success",
      });
    }

    clearSessionCookie(res);
    clearMfaPendingCookie(res);

    res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout error:", error);
    // Still clear cookies even on error
    clearSessionCookie(res);
    clearMfaPendingCookie(res);

    res.status(200).json({
      success: true,
      message: "Logged out",
    });
  }
};

/**
 * Logout all sessions
 */
export const logoutAllSessions = async (req, res) => {
  try {
    const currentSessionId = req.adminSession?._id;

    await AdminSession.revokeAllForAdmin(req.admin._id, currentSessionId, "logout_all");

    await AuditLog.log({
      admin: req.admin._id,
      category: "security",
      action: "logout_all_sessions",
      description: "All other sessions revoked",
      req,
      result: "success",
      severity: "medium",
    });

    res.status(200).json({
      success: true,
      message: "All other sessions have been logged out",
    });
  } catch (error) {
    console.error("Logout all error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to logout all sessions",
    });
  }
};

/**
 * Get Admin Profile
 */
export const getAdminProfile = async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin._id)
      .populate("role", "name displayName level")
      .populate("additionalPermissions", "code name");

    if (!admin) {
      return res.status(404).json({
        success: false,
        message: "Admin not found",
      });
    }

    // Get active sessions count
    const activeSessions = await AdminSession.countDocuments({
      admin: admin._id,
      isActive: true,
      expiresAt: { $gt: new Date() },
    });

    res.status(200).json({
      success: true,
      admin: {
        _id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
        mfaEnabled: admin.mfa.enabled,
        mfaRequired: admin.mfa.required,
        lastLogin: admin.security.lastLogin,
        activeSessions,
        createdAt: admin.createdAt,
      },
    });
  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({
      success: false,
      message: 'An unexpected error occurred',
    });
  }
};

/**
 * Get Active Sessions
 */
export const getActiveSessions = async (req, res) => {
  try {
    const sessions = await AdminSession.find({
      admin: req.admin._id,
      isActive: true,
      expiresAt: { $gt: new Date() },
    })
      .select("ipAddress userAgent deviceInfo createdAt lastActivity")
      .sort({ lastActivity: -1 });

    res.status(200).json({
      success: true,
      sessions: sessions.map((s) => ({
        _id: s._id,
        ipAddress: s.ipAddress,
        device: s.deviceInfo,
        createdAt: s.createdAt,
        lastActivity: s.lastActivity,
        isCurrent: s._id.toString() === req.adminSession._id.toString(),
      })),
    });
  } catch (error) {
    console.error("Get sessions error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to get sessions",
    });
  }
};

/**
 * Revoke specific session
 */
export const revokeSession = async (req, res) => {
  try {
    const { sessionId } = req.params;

    const session = await AdminSession.findOne({
      _id: sessionId,
      admin: req.admin._id,
    });

    if (!session) {
      return res.status(404).json({
        success: false,
        message: "Session not found",
      });
    }

    await session.revoke("manual_revoke");

    await AuditLog.log({
      admin: req.admin._id,
      category: "security",
      action: "session_revoked",
      resourceType: "session",
      resourceId: sessionId,
      description: "Session manually revoked",
      req,
      result: "success",
    });

    res.status(200).json({
      success: true,
      message: "Session revoked successfully",
    });
  } catch (error) {
    console.error("Revoke session error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to revoke session",
    });
  }
};

/**
 * Change Password
 */
export const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Current and new password are required",
      });
    }

    // ============================================
    // SECURITY FIX: Strong password validation for admins
    // ============================================
    const ADMIN_PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()\-_=+])[A-Za-z\d@$!%*?&#^()\-_=+]{12,}$/;

    if (!ADMIN_PASSWORD_REGEX.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message: "New password must be at least 12 characters and include uppercase, lowercase, number, and special character",
      });
    }

    const admin = await Admin.findById(req.admin._id).select("+password");

    // Verify current password
    const isValid = await bcrypt.compare(currentPassword, admin.password);
    if (!isValid) {
      await AuditLog.log({
        admin: admin._id,
        category: "security",
        action: "password_change_failed",
        description: "Password change failed - invalid current password",
        req,
        result: "failure",
        severity: "high",
        isSecurityEvent: true,
      });

      return res.status(401).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    // Update password (pre-save hook will hash it)
    admin.password = newPassword;
    admin.security.mustChangePassword = false;
    admin.security.passwordChangedAt = new Date();
    await admin.save();

    // Revoke all other sessions for security
    await AdminSession.revokeAllForAdmin(
      admin._id,
      req.adminSession._id,
      "password_changed"
    );

    await AuditLog.log({
      admin: admin._id,
      category: "security",
      action: "password_changed",
      description: "Password successfully changed",
      req,
      result: "success",
      severity: "medium",
      isSecurityEvent: true,
    });

    res.status(200).json({
      success: true,
      message: "Password changed successfully. Other sessions have been logged out.",
    });
  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({
      success: false,
      message: 'An unexpected error occurred' || "Failed to change password",
    });
  }
};

/**
 * Get Dashboard Statistics
 */
export const getDashboardStats = async (req, res) => {
  try {
    // Get counts
    const [totalUsers, totalProperties, totalLeads, approvedProperties, pendingProperties] =
      await Promise.all([
        User.countDocuments(),
        Property.countDocuments(),
        Lead.countDocuments(),
        Property.countDocuments({ isApproved: true }),
        Property.countDocuments({ isApproved: false }),
      ]);

    // Get properties by listing type
    const [rentCount, saleCount] = await Promise.all([
      Property.countDocuments({ listingType: { $regex: /rent/i } }),
      Property.countDocuments({ listingType: { $regex: /sell|sale|buy/i } }),
    ]);

    // Get lead stats
    const leadsByStatus = await Lead.aggregate([
      { $group: { _id: "$status", count: { $sum: 1 } } },
    ]);

    const leadStats = {
      new: 0,
      contacted: 0,
      interested: 0,
      negotiating: 0,
      converted: 0,
      lost: 0,
    };
    leadsByStatus.forEach((item) => {
      if (leadStats.hasOwnProperty(item._id)) {
        leadStats[item._id] = item.count;
      }
    });

    // Get monthly data for charts (last 6 months)
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const monthlyProperties = await Property.aggregate([
      { $match: { createdAt: { $gte: sixMonthsAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
          count: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    const monthlyLeads = await Lead.aggregate([
      { $match: { createdAt: { $gte: sixMonthsAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
          count: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    const monthlyUsers = await User.aggregate([
      { $match: { createdAt: { $gte: sixMonthsAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
          count: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    // Format monthly data for charts
    const formatMonthlyData = (data) => {
      const months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
      ];
      return data.map((item) => {
        const [year, month] = item._id.split("-");
        return {
          label: months[parseInt(month) - 1],
          value: item.count,
          month: item._id,
        };
      });
    };

    // Get recent properties
    const recentProperties = await Property.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate("owner", "name email")
      .select("title address.city price listingType isApproved createdAt images");

    // Get top owners by property count
    const topOwners = await Property.aggregate([
      { $group: { _id: "$owner", propertyCount: { $sum: 1 } } },
      { $sort: { propertyCount: -1 } },
      { $limit: 5 },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "ownerInfo",
        },
      },
      { $unwind: "$ownerInfo" },
      {
        $project: {
          name: "$ownerInfo.name",
          email: "$ownerInfo.email",
          propertyCount: 1,
        },
      },
    ]);

    // Log dashboard access
    await AuditLog.logAccess(
      req.admin,
      "dashboard",
      null,
      "view_stats",
      req,
      "success"
    );

    res.status(200).json({
      success: true,
      data: {
        counts: {
          totalUsers,
          totalProperties,
          totalLeads,
          approvedProperties,
          pendingProperties,
          rentCount,
          saleCount,
        },
        leadStats,
        charts: {
          properties: formatMonthlyData(monthlyProperties),
          leads: formatMonthlyData(monthlyLeads),
          users: formatMonthlyData(monthlyUsers),
        },
        recentProperties: recentProperties.map((p) => ({
          _id: p._id,
          title: p.title,
          city: p.address?.city || "N/A",
          price: p.price,
          listingType: p.listingType,
          isApproved: p.isApproved,
          createdAt: p.createdAt,
          owner: p.owner?.name || "Unknown",
          image: p.images?.[0] || null,
        })),
        topOwners,
      },
    });
  } catch (error) {
    console.error("Dashboard stats error:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

/**
 * Get All Leads (Admin)
 */
export const getAdminLeads = async (req, res) => {
  try {
    const { page = 1, limit = 20, status, search } = req.query;

    // Build filter
    let filter = {};
    if (status && status !== "all") {
      filter.status = status;
    }

    // Get leads
    let leads = await Lead.find(filter)
      .populate("user", "name email phone profileImage")
      .populate("propertyOwner", "name email phone")
      .populate("property", "title address.city price listingType images")
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit));

    // Apply search filter if provided
    if (search) {
      const searchLower = search.toLowerCase();
      leads = leads.filter(
        (lead) =>
          lead.userSnapshot?.name?.toLowerCase().includes(searchLower) ||
          lead.userSnapshot?.email?.toLowerCase().includes(searchLower) ||
          lead.propertySnapshot?.title?.toLowerCase().includes(searchLower) ||
          lead.propertySnapshot?.city?.toLowerCase().includes(searchLower)
      );
    }

    const total = await Lead.countDocuments(filter);

    // Get status stats
    const statusStats = await Lead.aggregate([
      { $group: { _id: "$status", count: { $sum: 1 } } },
    ]);

    const stats = {
      total: 0,
      new: 0,
      contacted: 0,
      interested: 0,
      negotiating: 0,
      converted: 0,
      lost: 0,
    };
    statusStats.forEach((s) => {
      if (stats.hasOwnProperty(s._id)) {
        stats[s._id] = s.count;
        stats.total += s.count;
      }
    });

    res.status(200).json({
      success: true,
      data: leads,
      stats,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
      },
    });
  } catch (error) {
    console.error("Admin leads error:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

/**
 * Update Lead Status (Admin)
 */
export const updateAdminLeadStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes } = req.body;

    const lead = await Lead.findById(id);
    if (!lead) {
      return res.status(404).json({ success: false, message: "Lead not found" });
    }

    const oldStatus = lead.status;
    if (status) lead.status = status;
    if (notes !== undefined) lead.notes = notes;

    await lead.save();

    await AuditLog.log({
      admin: req.admin._id,
      category: "lead_management",
      action: "lead_status_updated",
      resourceType: "lead",
      resourceId: id,
      description: `Lead status updated from ${oldStatus} to ${status}`,
      req,
      result: "success",
      changes: { before: { status: oldStatus }, after: { status } },
    });

    res.status(200).json({
      success: true,
      message: "Lead updated successfully",
      data: lead,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

/**
 * Get Reports (Admin)
 */
export const getAdminReports = async (req, res) => {
  try {
    const { page = 1, limit = 20, status, type } = req.query;

    let filter = {};
    if (type && type !== "all") {
      filter.contextType = type;
    } else {
      filter.contextType = "message";
    }
    if (status && status !== "all") {
      filter.status = status;
    }

    const reports = await Report.find(filter)
      .populate("reportedBy", "name email")
      .populate({
        path: "message",
        populate: { path: "sender", select: "name email role" },
      })
      .populate({
        path: "property",
        populate: { path: "owner", select: "name email role" },
      })
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit));

    const total = await Report.countDocuments(filter);

    res.status(200).json({
      success: true,
      data: reports,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
      },
    });
  } catch (error) {
    console.error("Admin reports error:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

/**
 * Update Report Status (Admin)
 */
export const updateReportStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminNotes } = req.body;

    const report = await Report.findById(id);
    if (!report) {
      return res.status(404).json({ success: false, message: "Report not found" });
    }

    const oldStatus = report.status;
    if (status) report.status = status;
    if (adminNotes !== undefined) report.adminNotes = adminNotes;

    if (["reviewed", "resolved", "dismissed"].includes(status)) {
      report.reviewedBy = req.admin._id;
      report.reviewedAt = new Date();
    }

    await report.save();

    await AuditLog.log({
      admin: req.admin._id,
      category: "report_management",
      action: "report_status_updated",
      resourceType: "report",
      resourceId: id,
      description: `Report status updated from ${oldStatus} to ${status}`,
      req,
      result: "success",
      changes: { before: { status: oldStatus }, after: { status } },
    });

    res.status(200).json({
      success: true,
      message: "Report updated successfully",
      data: report,
    });
  } catch (error) {
    console.error("Update report error:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

/**
 * Get Audit Logs (Super Admin only)
 */
export const getAuditLogs = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      category,
      action,
      adminId,
      startDate,
      endDate,
      severity,
      securityOnly,
    } = req.query;

    const filter = {};

    if (category) filter.category = category;
    // ============================================
    // SECURITY FIX: ReDoS/Injection Prevention
    // Previously: action was passed directly to $regex
    // Now: Escape special regex characters before creating pattern
    // ============================================
    if (action) {
      // Escape special regex characters to prevent ReDoS
      const escapedAction = action.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.action = { $regex: escapedAction, $options: "i" };
    }
    if (adminId) filter.admin = adminId;
    if (severity) filter.severity = severity;
    if (securityOnly === "true") filter.isSecurityEvent = true;

    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }

    const logs = await AuditLog.find(filter)
      .populate("admin", "name email")
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit));

    const total = await AuditLog.countDocuments(filter);

    res.status(200).json({
      success: true,
      data: logs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
      },
    });
  } catch (error) {
    console.error("Get audit logs error:", error);
    res.status(500).json({ success: false, message: 'An unexpected error occurred' });
  }
};

/**
 * Create default roles (called during first admin registration)
 */
async function createDefaultRoles() {
  const defaultRoles = [
    {
      name: "super_admin",
      displayName: "Super Administrator",
      description: "Full system access with all privileges",
      level: 100,
      canManageAdmins: true,
      isSystem: true,
    },
    {
      name: "admin",
      displayName: "Administrator",
      description: "Administrative access to most features",
      level: 80,
      canManageAdmins: false,
      isSystem: true,
    },
    {
      name: "manager",
      displayName: "Manager",
      description: "Management access to properties and leads",
      level: 50,
      canManageAdmins: false,
      isSystem: true,
    },
    {
      name: "viewer",
      displayName: "Viewer",
      description: "Read-only access to dashboard and reports",
      level: 10,
      canManageAdmins: false,
      isSystem: true,
    },
  ];

  for (const roleData of defaultRoles) {
    await Role.findOneAndUpdate({ name: roleData.name }, roleData, {
      upsert: true,
      new: true,
    });
  }

  return await Role.findOne({ name: "viewer" });
}
