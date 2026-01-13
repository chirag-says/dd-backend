/**
 * User Model - Enterprise Security Enhanced
 * Secure user schema with session tracking and security features
 */
import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      maxlength: [100, "Name cannot exceed 100 characters"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, "Please provide a valid email"],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 characters"],
      select: false, // Never return password by default
    },
    role: {
      type: String,
      // 'user' and 'buyer' are equivalent - buyers/seekers. 'owner' = sellers
      // Both values accepted for backward compatibility
      enum: ["user", "buyer", "owner"],
      default: "buyer", // New users default to buyer role
    },

    // Profile fields
    phone: {
      type: String,
      match: [/^[6-9]\d{9}$/, "Please provide a valid 10-digit phone number"],
    },
    alternatePhone: { type: String },
    address: {
      line1: { type: String },
      line2: { type: String },
      city: { type: String },
      state: { type: String },
      pincode: { type: String },
    },
    profileImage: { type: String },
    dateOfBirth: { type: Date },
    gender: { type: String, enum: ["Male", "Female", "Other", ""] },
    bio: {
      type: String,
      maxlength: [500, "Bio cannot exceed 500 characters"],
    },

    // Account Status
    isActive: {
      type: Boolean,
      default: true,
    },
    isBlocked: {
      type: Boolean,
      default: false
    },
    blockReason: {
      type: String,
      default: "",
      select: false, // Only admin should see this
    },
    blockedAt: {
      type: Date,
      select: false,
    },
    blockedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
      select: false,
    },

    // Preferences
    preferences: {
      emailNotifications: { type: Boolean, default: true },
      smsNotifications: { type: Boolean, default: false },
    },

    // Email Verification
    isVerified: {
      type: Boolean,
      default: false
    },
    otp: {
      type: String,
      select: false, // Never return OTP in queries
    },
    otpExpires: {
      type: Date,
      select: false,
    },

    // Security Fields
    security: {
      // Failed login tracking
      failedLoginAttempts: {
        type: Number,
        default: 0,
        select: false,
      },
      lockoutUntil: {
        type: Date,
        default: null,
        select: false,
      },
      // Password change tracking
      passwordChangedAt: {
        type: Date,
        default: null,
      },
      // Last login tracking
      lastLoginAt: {
        type: Date,
        default: null,
      },
      lastLoginIp: {
        type: String,
        default: null,
        select: false,
      },
      // Session version (increment to invalidate all sessions)
      sessionVersion: {
        type: Number,
        default: 0,
      },
    },

    // Deprecated fields - kept for migration compatibility
    resetPasswordOtp: {
      type: String,
      select: false,
    },
    resetPasswordOtpExpires: {
      type: Date,
      select: false,
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform: function (doc, ret) {
        // Remove sensitive fields from JSON output
        delete ret.password;
        delete ret.otp;
        delete ret.otpExpires;
        delete ret.resetPasswordOtp;
        delete ret.resetPasswordOtpExpires;
        delete ret.blockReason;
        delete ret.blockedAt;
        delete ret.blockedBy;
        delete ret.__v;
        if (ret.security) {
          delete ret.security.failedLoginAttempts;
          delete ret.security.lockoutUntil;
          delete ret.security.lastLoginIp;
        }
        return ret;
      }
    }
  }
);

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ role: 1 });
userSchema.index({ isVerified: 1 });
userSchema.index({ isBlocked: 1 });
userSchema.index({ createdAt: -1 });

// Virtual for full address
userSchema.virtual("fullAddress").get(function () {
  if (!this.address) return null;
  const parts = [
    this.address.line1,
    this.address.line2,
    this.address.city,
    this.address.state,
    this.address.pincode,
  ].filter(Boolean);
  return parts.join(", ");
});

// Instance method: Check if account is locked
userSchema.methods.isLocked = function () {
  return this.security?.lockoutUntil && this.security.lockoutUntil > new Date();
};

// Instance method: Increment failed login attempts
userSchema.methods.incrementFailedLogins = async function () {
  const maxAttempts = 5;
  const lockoutMinutes = 15;

  this.security = this.security || {};
  this.security.failedLoginAttempts = (this.security.failedLoginAttempts || 0) + 1;

  if (this.security.failedLoginAttempts >= maxAttempts) {
    this.security.lockoutUntil = new Date(Date.now() + lockoutMinutes * 60 * 1000);
  }

  await this.save();
};

// Instance method: Reset failed login attempts
userSchema.methods.resetFailedLogins = async function () {
  this.security = this.security || {};
  this.security.failedLoginAttempts = 0;
  this.security.lockoutUntil = null;
  await this.save();
};

// Instance method: Update last login
userSchema.methods.updateLastLogin = async function (ip) {
  this.security = this.security || {};
  this.security.lastLoginAt = new Date();
  this.security.lastLoginIp = ip;
  await this.save();
};

// Instance method: Check if password changed after token issued
userSchema.methods.changedPasswordAfter = function (jwtTimestamp) {
  if (this.security?.passwordChangedAt) {
    const changedTimestamp = parseInt(this.security.passwordChangedAt.getTime() / 1000, 10);
    return jwtTimestamp < changedTimestamp;
  }
  return false;
};

// Instance method: Invalidate all sessions (increment version)
userSchema.methods.invalidateSessions = async function () {
  this.security = this.security || {};
  this.security.sessionVersion = (this.security.sessionVersion || 0) + 1;
  await this.save();
};

// Static method: Filter safe fields for API response
userSchema.statics.getSafeFields = function () {
  return "-password -otp -otpExpires -resetPasswordOtp -resetPasswordOtpExpires -blockReason -blockedAt -blockedBy -security.failedLoginAttempts -security.lockoutUntil -security.lastLoginIp";
};

// Static method: Get public profile fields
userSchema.statics.getPublicFields = function () {
  return "name profileImage role bio";
};

const User = mongoose.model("User", userSchema);
export default User;
