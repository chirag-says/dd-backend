import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";

// Import related models to ensure they're registered
import "./Permission.js";
import "./Role.js";

/**
 * Enhanced Admin Schema
 * Enterprise-grade admin model with MFA support, role-based access, and security features
 */
const adminSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Please add name"],
      trim: true,
      maxlength: [100, "Name cannot exceed 100 characters"],
    },
    email: {
      type: String,
      required: [true, "Please add email"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, "Please enter a valid email"],
    },
    password: {
      type: String,
      required: [true, "Please add password"],
      minlength: [12, "Password must be at least 12 characters"],
      select: false, // Don't include password by default in queries
    },
    // Role - supports both legacy string roles ("admin") and new ObjectId references
    // Legacy admins have string roles, new admins have ObjectId refs to Role collection
    role: {
      type: mongoose.Schema.Types.Mixed, // Accepts both String and ObjectId
      required: false,
    },
    // Direct permissions (in addition to role permissions)
    additionalPermissions: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Permission",
      },
    ],
    // Multi-Factor Authentication
    mfa: {
      enabled: {
        type: Boolean,
        default: false,
      },
      required: {
        type: Boolean,
        default: true, // MFA is required by default for admins
      },
      secret: {
        type: String,
        select: false,
      },
      backupCodes: {
        type: [String],
        select: false,
      },
      lastVerified: {
        type: Date,
        default: null,
      },
    },
    // Security tracking
    security: {
      failedLoginAttempts: {
        type: Number,
        default: 0,
      },
      lockoutUntil: {
        type: Date,
        default: null,
      },
      lastLogin: {
        type: Date,
        default: null,
      },
      lastLoginIp: {
        type: String,
        default: null,
      },
      passwordChangedAt: {
        type: Date,
        default: Date.now,
      },
      mustChangePassword: {
        type: Boolean,
        default: false,
      },
    },
    // Account status
    isActive: {
      type: Boolean,
      default: true,
      index: true,
    },
    // Soft delete support
    deletedAt: {
      type: Date,
      default: null,
    },
    // Created by (for audit trail)
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      default: null,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Indexes
adminSchema.index({ email: 1 });
adminSchema.index({ isActive: 1, deletedAt: 1 });
adminSchema.index({ role: 1 });

// Virtual for checking if account is locked (with null safety for legacy admins)
adminSchema.virtual("isLocked").get(function () {
  return !!(this.security?.lockoutUntil && this.security.lockoutUntil > new Date());
});

// Pre-save hook to hash password
adminSchema.pre("save", async function (next) {
  // Only hash if password is modified
  if (!this.isModified("password")) {
    return next();
  }

  // Validate password strength
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
  if (!passwordRegex.test(this.password)) {
    const err = new Error(
      "Password must be at least 12 characters with uppercase, lowercase, number, and special character"
    );
    return next(err);
  }

  // Hash password with cost factor 12
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  this.security.passwordChangedAt = new Date();

  next();
});

/**
 * Compare entered password with hashed password
 */
adminSchema.methods.comparePassword = async function (enteredPassword) {
  // Need to explicitly select password for comparison
  const admin = await this.constructor.findById(this._id).select("+password");
  return bcrypt.compare(enteredPassword, admin.password);
};

/**
 * Increment failed login attempts and lock account if necessary
 */
adminSchema.methods.incrementLoginAttempts = async function () {
  const MAX_ATTEMPTS = 5;
  const LOCK_DURATION = 30 * 60 * 1000; // 30 minutes

  // Initialize security object for legacy admins
  if (!this.security) {
    this.security = {};
  }

  // If lock has expired, reset attempts
  if (this.security.lockoutUntil && this.security.lockoutUntil < new Date()) {
    this.security.failedLoginAttempts = 1;
    this.security.lockoutUntil = null;
  } else {
    this.security.failedLoginAttempts = (this.security.failedLoginAttempts || 0) + 1;

    // Lock account if max attempts reached
    if (this.security.failedLoginAttempts >= MAX_ATTEMPTS) {
      this.security.lockoutUntil = new Date(Date.now() + LOCK_DURATION);
    }
  }

  return this.save();
};

/**
 * Reset login attempts on successful login
 */
adminSchema.methods.resetLoginAttempts = async function (ipAddress) {
  // Initialize security object for legacy admins
  if (!this.security) {
    this.security = {};
  }
  this.security.failedLoginAttempts = 0;
  this.security.lockoutUntil = null;
  this.security.lastLogin = new Date();
  this.security.lastLoginIp = ipAddress;
  return this.save();
};

/**
 * Generate MFA backup codes
 */
adminSchema.methods.generateBackupCodes = function () {
  const codes = [];
  for (let i = 0; i < 10; i++) {
    codes.push(crypto.randomBytes(4).toString("hex").toUpperCase());
  }
  return codes;
};

/**
 * Hash backup codes for storage
 */
adminSchema.methods.hashBackupCodes = async function (codes) {
  const hashedCodes = await Promise.all(codes.map((code) => bcrypt.hash(code, 10)));
  return hashedCodes;
};

/**
 * Verify a backup code
 */
adminSchema.methods.verifyBackupCode = async function (code) {
  const admin = await this.constructor.findById(this._id).select("+mfa.backupCodes");
  if (!admin.mfa.backupCodes || admin.mfa.backupCodes.length === 0) {
    return false;
  }

  for (let i = 0; i < admin.mfa.backupCodes.length; i++) {
    const isMatch = await bcrypt.compare(code.toUpperCase(), admin.mfa.backupCodes[i]);
    if (isMatch) {
      // Remove used backup code
      admin.mfa.backupCodes.splice(i, 1);
      await admin.save();
      return true;
    }
  }

  return false;
};

/**
 * Check if password was changed after token was issued
 */
adminSchema.methods.changedPasswordAfter = function (tokenIssuedAt) {
  if (this.security.passwordChangedAt) {
    const changedTimestamp = parseInt(this.security.passwordChangedAt.getTime() / 1000, 10);
    return tokenIssuedAt < changedTimestamp;
  }
  return false;
};
/**
 * Get all permissions (from role + additional)
 * NOTE: Role field is Mixed type, so populate() doesn't work - we fetch manually
 */
adminSchema.methods.getPermissions = async function () {
  try {
    // Import models dynamically to avoid circular dependency
    const Role = mongoose.model('Role');
    const Permission = mongoose.model('Permission');

    // Handle string roles (legacy)
    if (typeof this.role === 'string') {
      console.warn(`[SECURITY] Admin ${this._id} has legacy string role "${this.role}" - migration required`);
      // Return read-only permissions - admin must be migrated to proper Role
      return ["dashboard:read", "dashboard:view", "properties:read"];
    }

    // Handle missing role
    if (!this.role) {
      console.error(`[SECURITY] Admin ${this._id} has no role configured - access restricted`);
      return [];
    }

    // Fetch the Role document with permissions populated
    const roleDoc = await Role.findById(this.role).populate('permissions');

    if (!roleDoc) {
      console.error(`[SECURITY] Admin ${this._id} role ${this.role} not found in database`);
      return [];
    }

    // Get permission codes from role
    const rolePermissions = roleDoc.permissions || [];

    // Fetch additional permissions if any
    let additionalPerms = [];
    if (this.additionalPermissions && this.additionalPermissions.length > 0) {
      additionalPerms = await Permission.find({ _id: { $in: this.additionalPermissions } });
    }

    // Combine and deduplicate permission codes
    const allPermissions = [...rolePermissions, ...additionalPerms];
    const uniqueCodes = [...new Set(allPermissions.map((p) => p?.code).filter(Boolean))];

    // ============================================
    // SECURITY FIX: Do NOT grant permissions on empty result
    // This prevents privilege escalation via corrupted Role references
    // ============================================
    if (uniqueCodes.length === 0) {
      console.error(`[SECURITY] Admin ${this._id} has 0 permissions from Role - verify role configuration`);
      // Return empty - admin will be denied access until role is fixed
      return [];
    }

    return uniqueCodes;
  } catch (err) {
    console.error("Error getting permissions:", err.message);
    return ["dashboard:view"]; // Fallback to minimal permissions
  }
};

/**
 * Check if admin has a specific permission
 */
adminSchema.methods.hasPermission = async function (permissionCode) {
  const permissions = await this.getPermissions();
  return permissions.includes(permissionCode);
};

/**
 * Check if admin has any of the specified permissions
 */
adminSchema.methods.hasAnyPermission = async function (permissionCodes) {
  const permissions = await this.getPermissions();
  return permissionCodes.some((code) => permissions.includes(code));
};

/**
 * Check if admin has all specified permissions
 */
adminSchema.methods.hasAllPermissions = async function (permissionCodes) {
  const permissions = await this.getPermissions();
  return permissionCodes.every((code) => permissions.includes(code));
};

// Query middleware to exclude soft-deleted by default
adminSchema.pre(/^find/, function (next) {
  // Only apply if not explicitly querying deleted
  if (!this.getOptions().includeDeleted) {
    this.where({ deletedAt: null });
  }
  next();
});

export default mongoose.model("Admin", adminSchema);
