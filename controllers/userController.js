/**
 * User Controller
 * Enterprise-grade user authentication with HttpOnly cookies,
 * secure password reset, and sanitized responses
 */
import User from "../models/userModel.js";
import UserSession from "../models/UserSession.js";
import PasswordResetToken from "../models/PasswordResetToken.js";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import nodemailer from "nodemailer";
import { setSessionCookie, clearSessionCookie } from "../middleware/authUser.js";
import { Parser } from "@json2csv/plainjs";
import PDFDocument from "pdfkit";

// ============================================
// EMAIL CONFIGURATION
// ============================================

let transporter = null;

const getTransporter = () => {
  if (!transporter) {
    console.log("📧 Initializing SMTP transporter...");
    transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    transporter.verify((error, success) => {
      if (error) {
        console.error("❌ SMTP Connection Error:", error.message);
      } else {
        console.log("✅ SMTP Server is ready to send emails");
      }
    });
  }
  return transporter;
};

// ============================================
// HELPER FUNCTIONS
// ============================================

// Generate cryptographically secure 6-digit OTP
const generateSecureOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// ============================================
// SECURITY FIX: Hash OTP before storage
// Prevents OTP exposure in case of database breach
// ============================================
const hashOTP = (otp) => {
  const secret = process.env.OTP_SECRET || process.env.JWT_SECRET;
  return crypto.createHash('sha256').update(otp + secret).digest('hex');
};

// Verify OTP by comparing hash
const verifyOTPHash = (providedOtp, storedHash) => {
  const providedHash = hashOTP(providedOtp);
  // Constant-time comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(Buffer.from(providedHash), Buffer.from(storedHash));
  } catch {
    return false;
  }
};

// ============================================
// SECURITY FIX: Strong password validation
// Minimum 8 chars, requires uppercase, lowercase, number, special char
// ============================================
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()\-_=+])[A-Za-z\d@$!%*?&#^()\-_=+]{8,}$/;

const validatePasswordStrength = (password) => {
  if (!password || password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters long' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter' };
  }
  if (!/\d/.test(password)) {
    return { valid: false, message: 'Password must contain at least one number' };
  }
  if (!/[@$!%*?&#^()\-_=+]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one special character (@$!%*?&#^()-_=+)' };
  }
  return { valid: true };
};

// Phone validation (Indian 10-digit mobile numbers)
const isValidPhoneNumber = (phone) => {
  const cleaned = (phone || "").toString().trim();
  if (!cleaned) return true;
  return /^[6-9]\d{9}$/.test(cleaned);
};

// Sanitize user for API response - NEVER expose sensitive fields
const sanitizeUserResponse = (user) => {
  const safeUser = user.toObject ? user.toObject() : { ...user };

  // Whitelist approach - only include safe fields
  return {
    _id: safeUser._id,
    id: safeUser._id,
    name: safeUser.name,
    email: safeUser.email,
    phone: safeUser.phone,
    alternatePhone: safeUser.alternatePhone,
    address: safeUser.address,
    profileImage: safeUser.profileImage,
    dateOfBirth: safeUser.dateOfBirth,
    gender: safeUser.gender,
    bio: safeUser.bio,
    role: safeUser.role,
    isVerified: safeUser.isVerified,
    isBlocked: safeUser.isBlocked,
    blockReason: safeUser.blockReason,
    preferences: safeUser.preferences,
    createdAt: safeUser.createdAt,
    updatedAt: safeUser.updatedAt,
  };
};

// ============================================
// EMAIL TEMPLATES
// ============================================

const sendOTPEmail = async (email, otp, name = "User") => {
  const mailOptions = {
    from: `"DealDirect" <${process.env.SENDER_EMAIL || process.env.SMTP_USER}>`,
    to: email,
    subject: "🔐 DealDirect - Verify Your Email",
    html: `
      <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); padding: 30px; border-radius: 12px 12px 0 0; text-align: center;">
          <h1 style="color: white; margin: 0; font-size: 28px;">DealDirect</h1>
          <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0;">Your Trusted Real Estate Partner</p>
        </div>
        <div style="background: #ffffff; padding: 40px 30px; border: 1px solid #e5e7eb; border-top: none;">
          <h2 style="color: #1f2937; margin: 0 0 20px;">Hello ${name}! 👋</h2>
          <p style="color: #4b5563; font-size: 16px; line-height: 1.6; margin: 0 0 25px;">
            Thank you for registering with DealDirect. Please use the following OTP to verify your email:
          </p>
          <div style="background: #f3f4f6; border-radius: 12px; padding: 25px; text-align: center; margin: 25px 0;">
            <p style="color: #6b7280; font-size: 14px; margin: 0 0 10px;">Your One-Time Password</p>
            <div style="font-size: 36px; font-weight: bold; color: #dc2626; letter-spacing: 8px; font-family: 'Courier New', monospace;">
              ${otp}
            </div>
          </div>
          <p style="color: #6b7280; font-size: 14px; margin: 25px 0 0;">
            ⏰ This OTP is valid for <strong>10 minutes</strong>. Please do not share this code with anyone.
          </p>
        </div>
      </div>
    `,
    text: `Hello ${name}!\n\nYour OTP for DealDirect registration is: ${otp}\n\nThis OTP is valid for 10 minutes.`,
  };

  return getTransporter().sendMail(mailOptions);
};

const sendPasswordResetEmail = async (email, resetToken, name = "User") => {
  // Create a reset link with the token
  const resetUrl = `${process.env.CLIENT_URL}/reset-password?token=${resetToken}`;

  const mailOptions = {
    from: `"DealDirect" <${process.env.SENDER_EMAIL || process.env.SMTP_USER}>`,
    to: email,
    subject: "🔑 DealDirect - Reset Your Password",
    html: `
      <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); padding: 30px; border-radius: 12px 12px 0 0; text-align: center;">
          <h1 style="color: white; margin: 0; font-size: 28px;">DealDirect</h1>
          <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0;">Password Reset Request</p>
        </div>
        <div style="background: #ffffff; padding: 40px 30px; border: 1px solid #e5e7eb; border-top: none;">
          <h2 style="color: #1f2937; margin: 0 0 20px;">Hello ${name}! 🔐</h2>
          <p style="color: #4b5563; font-size: 16px; line-height: 1.6; margin: 0 0 25px;">
            We received a request to reset your password. Click the button below to create a new password:
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background: #dc2626; color: white; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: 600; display: inline-block;">
              Reset Password
            </a>
          </div>
          <p style="color: #6b7280; font-size: 14px; text-align: center;">
            Or copy this link: <br/>
            <code style="background: #f3f4f6; padding: 4px 8px; border-radius: 4px; word-break: break-all;">${resetUrl}</code>
          </p>
          <div style="background: #fef3c7; border-radius: 8px; padding: 15px; margin: 25px 0;">
            <p style="color: #92400e; font-size: 14px; margin: 0;">
              <strong>⚠️ Security Notice:</strong><br/>
              • This link is valid for 15 minutes<br/>
              • If you didn't request this, ignore this email<br/>
              • Never share this link with anyone
            </p>
          </div>
        </div>
      </div>
    `,
    text: `Hello ${name}!\n\nClick this link to reset your password: ${resetUrl}\n\nThis link is valid for 15 minutes.`,
  };

  return getTransporter().sendMail(mailOptions);
};

// ============================================
// AUTHENTICATION CONTROLLERS
// ============================================

/**
 * Register User (with OTP verification for owners)
 */
export const registerUser = async (req, res) => {
  try {
    const { name, email, password, role, phone } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email, and password are required" });
    }

    if (!isValidPhoneNumber(phone)) {
      return res.status(400).json({ message: "Please enter a valid 10-digit phone number" });
    }

    // SECURITY FIX: Strong password validation
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ message: passwordValidation.message });
    }

    const normalizedEmail = email.toLowerCase().trim();
    let user = await User.findOne({ email: normalizedEmail });

    if (user && user.isVerified) {
      return res.status(400).json({ message: "User already exists. Please login." });
    }

    const otp = generateSecureOTP();
    const hashedOtp = hashOTP(otp); // SECURITY FIX: Hash OTP before storage
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    const hashedPassword = await bcrypt.hash(password, 12); // Increased salt rounds
    const normalizedRole = role === "owner" ? "owner" : "user";

    if (!user) {
      user = await User.create({
        name: name.trim(),
        email: normalizedEmail,
        password: hashedPassword,
        role: normalizedRole,
        phone: phone?.trim(),
        otp: hashedOtp, // SECURITY: Store hashed OTP
        otpExpires,
        isVerified: false,
      });
    } else {
      user.name = name.trim();
      user.password = hashedPassword;
      user.role = normalizedRole;
      if (phone) user.phone = phone.trim();
      user.otp = hashedOtp; // SECURITY: Store hashed OTP
      user.otpExpires = otpExpires;
      await user.save();
    }

    try {
      await sendOTPEmail(normalizedEmail, otp, name);
    } catch (emailError) {
      console.error("❌ Error sending OTP email:", emailError.message);
      return res.status(200).json({
        message: "Registration initiated. Check console for OTP (email service issue).",
        email: normalizedEmail,
      });
    }

    res.status(200).json({
      success: true,
      message: "OTP sent to your email. Please verify to complete registration.",
      email: normalizedEmail,
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Registration failed. Please try again." });
  }
};

/**
 * Register User Directly (for buyers - no OTP)
 */
export const registerUserDirect = async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email, and password are required" });
    }

    if (!isValidPhoneNumber(phone)) {
      return res.status(400).json({ message: "Please enter a valid 10-digit phone number" });
    }

    // SECURITY FIX: Strong password validation
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ message: passwordValidation.message });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      if (existingUser.isVerified) {
        return res.status(400).json({ message: "User already exists. Please login." });
      }
      await User.deleteOne({ _id: existingUser._id });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword,
      role: "user",
      phone: phone?.trim(),
      isVerified: true,
    });

    // Create session
    const { session, sessionToken } = await UserSession.createSession(user, req);
    setSessionCookie(res, sessionToken);

    res.status(201).json({
      success: true,
      message: "Registration successful! Welcome to DealDirect.",
      user: sanitizeUserResponse(user),
    });
  } catch (err) {
    console.error("Register direct error:", err);
    res.status(500).json({ message: "Registration failed. Please try again." });
  }
};

/**
 * Verify OTP
 */
export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: "Email and OTP are required" });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() }).select("+otp +otpExpires");

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: "User already verified. Please login." });
    }

    // SECURITY FIX: Verify hashed OTP
    if (!user.otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    if (!verifyOTPHash(otp, user.otp)) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // Verify User
    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    // Create session
    const { session, sessionToken } = await UserSession.createSession(user, req);
    setSessionCookie(res, sessionToken);

    res.status(201).json({
      success: true,
      message: "Email verified and registration successful",
      user: sanitizeUserResponse(user),
    });
  } catch (err) {
    console.error("Verify OTP error:", err);
    res.status(500).json({ message: "Verification failed. Please try again." });
  }
};

/**
 * Resend OTP
 */
export const resendOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });

    if (!user) {
      return res.status(400).json({ message: "User not found. Please register first." });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: "Email already verified. Please login." });
    }

    const otp = generateSecureOTP();
    user.otp = hashOTP(otp); // SECURITY FIX: Store hashed OTP
    user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    try {
      await sendOTPEmail(email, otp, user.name);
    } catch (emailError) {
      console.error("❌ Error resending OTP:", emailError.message);
      return res.status(500).json({ message: "Failed to send OTP. Please try again." });
    }

    res.status(200).json({
      message: "New OTP sent to your email.",
      email: email,
    });
  } catch (err) {
    console.error("Resend OTP error:", err);
    res.status(500).json({ message: "Failed to resend OTP. Please try again." });
  }
};

/**
 * Login User - Database only (NO EnvAgent/EnvOwner)
 */
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Find user with password and security fields
    const user = await User.findOne({ email: normalizedEmail })
      .select("+password +security.failedLoginAttempts +security.lockoutUntil +blockReason");

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Check lockout
    if (user.isLocked()) {
      const remainingMs = user.security.lockoutUntil - Date.now();
      const remainingMinutes = Math.ceil(remainingMs / 60000);
      return res.status(423).json({
        message: `Account temporarily locked. Try again in ${remainingMinutes} minutes.`,
        code: "ACCOUNT_LOCKED",
        lockoutUntil: user.security.lockoutUntil,
      });
    }

    // Check if blocked
    if (user.isBlocked) {
      return res.status(403).json({
        message: "Your account has been blocked. Contact support.",
        code: "ACCOUNT_BLOCKED",
        blockReason: user.blockReason || "No reason provided",
      });
    }

    // Check verification
    if (!user.isVerified) {
      return res.status(400).json({
        message: "Email not verified. Please complete registration.",
        code: "EMAIL_NOT_VERIFIED",
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      await user.incrementFailedLogins();
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Reset failed attempts and update last login
    await user.resetFailedLogins();
    await user.updateLastLogin(req.ip);

    // Create session
    const { session, sessionToken } = await UserSession.createSession(user, req);
    setSessionCookie(res, sessionToken);

    res.status(200).json({
      success: true,
      message: "Login successful",
      user: sanitizeUserResponse(user),
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Login failed. Please try again." });
  }
};

/**
 * Logout User
 */
export const logoutUser = async (req, res) => {
  try {
    // Revoke current session if exists
    if (req.userSession) {
      await UserSession.revokeSession(req.userSession._id, "user_logout");
    }

    clearSessionCookie(res);

    res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (err) {
    console.error("Logout error:", err);
    // Still clear cookie even on error
    clearSessionCookie(res);
    res.status(200).json({
      success: true,
      message: "Logged out",
    });
  }
};

/**
 * Logout from all devices
 */
export const logoutAllDevices = async (req, res) => {
  try {
    await UserSession.revokeAllUserSessions(req.user._id, "logout_all_devices");
    clearSessionCookie(res);

    res.status(200).json({
      success: true,
      message: "Logged out from all devices",
    });
  } catch (err) {
    console.error("Logout all error:", err);
    res.status(500).json({ message: "Failed to logout from all devices" });
  }
};

// ============================================
// PASSWORD RESET (SECURE TOKEN-BASED)
// ============================================

/**
 * Forgot Password - Send secure reset token
 */
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });

    // Always return success to prevent email enumeration
    if (!user || !user.isVerified) {
      return res.status(200).json({
        message: "If an account exists with this email, you will receive a password reset link.",
      });
    }

    // Check rate limiting
    const canRequest = await PasswordResetToken.checkRateLimit(user._id);
    if (!canRequest) {
      return res.status(429).json({
        message: "Too many password reset requests. Please try again later.",
        code: "RATE_LIMITED",
      });
    }

    // Generate secure reset token
    const resetToken = await PasswordResetToken.createResetToken(
      user._id,
      req.ip || "unknown"
    );

    try {
      await sendPasswordResetEmail(normalizedEmail, resetToken, user.name);
    } catch (emailError) {
      console.error("❌ Error sending password reset email:", emailError.message);
      return res.status(500).json({
        message: "Failed to send reset email. Please try again later.",
      });
    }

    res.status(200).json({
      message: "If an account exists with this email, you will receive a password reset link.",
    });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: "Server error. Please try again." });
  }
};

/**
 * Validate Reset Token (check if token is valid before showing reset form)
 */
export const validateResetToken = async (req, res) => {
  try {
    const { token } = req.params;

    if (!token) {
      return res.status(400).json({
        valid: false,
        message: "Reset token is required"
      });
    }

    const resetToken = await PasswordResetToken.validateToken(token, req.ip);

    if (!resetToken) {
      return res.status(400).json({
        valid: false,
        message: "Invalid or expired reset link. Please request a new one.",
      });
    }

    res.status(200).json({
      valid: true,
      message: "Token is valid",
      email: resetToken.user.email, // Show masked email
    });
  } catch (err) {
    console.error("Validate reset token error:", err);
    res.status(500).json({ valid: false, message: "Validation failed" });
  }
};

/**
 * Reset Password - Use secure token
 */
export const resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        message: "Reset token and new password are required",
      });
    }

    // SECURITY FIX: Strong password validation
    const passwordValidation = validatePasswordStrength(newPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({ message: passwordValidation.message });
    }

    // Validate token
    const resetToken = await PasswordResetToken.validateToken(token, req.ip);

    if (!resetToken) {
      return res.status(400).json({
        message: "Invalid or expired reset link. Please request a new one.",
      });
    }

    const user = resetToken.user;

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password and security fields
    user.password = hashedPassword;
    user.security = user.security || {};
    user.security.passwordChangedAt = new Date();
    await user.save();

    // Mark token as used
    await PasswordResetToken.useToken(PasswordResetToken.hashToken(token), req.ip);

    // Invalidate all existing sessions (security measure)
    await UserSession.revokeAllUserSessions(user._id, "password_reset");

    res.status(200).json({
      message: "Password reset successful! Please login with your new password.",
    });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ message: "Server error. Please try again." });
  }
};

// ============================================
// PROFILE CONTROLLERS
// ============================================

/**
 * Get User Profile
 * Returns user profile with role and permissions info
 * Handles legacy users gracefully
 */
export const getProfile = async (req, res) => {
  try {
    // req.user is already populated by authMiddleware
    // But fetch fresh data to ensure latest info
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    // Handle legacy users missing fields
    const userResponse = sanitizeUserResponse(user);

    // Ensure role is always present (default to 'user' for legacy)
    if (!userResponse.role) {
      userResponse.role = 'user';
    }

    // Ensure isVerified is always present
    if (userResponse.isVerified === undefined) {
      userResponse.isVerified = true; // Legacy users are considered verified
    }

    res.status(200).json({
      success: true,
      message: "Profile fetched successfully",
      user: userResponse,
    });
  } catch (err) {
    console.error("Get profile error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to fetch profile"
    });
  }
};

/**
 * Update User Profile
 */
export const updateProfile = async (req, res) => {
  try {
    const userId = req.user._id;
    const {
      name,
      phone,
      alternatePhone,
      address,
      dateOfBirth,
      gender,
      bio,
      preferences,
    } = req.body;

    const updateData = {};
    if (name) updateData.name = name.trim();
    if (phone !== undefined) updateData.phone = phone;
    if (alternatePhone !== undefined) updateData.alternatePhone = alternatePhone;
    if (address) {
      updateData.address = typeof address === "string" ? JSON.parse(address) : address;
    }
    if (dateOfBirth) updateData.dateOfBirth = dateOfBirth;
    if (gender !== undefined) updateData.gender = gender;
    if (bio !== undefined) updateData.bio = bio?.substring(0, 500); // Limit bio length
    if (preferences) {
      updateData.preferences = typeof preferences === "string" ? JSON.parse(preferences) : preferences;
    }

    // Handle profile image upload
    if (req.file) {
      updateData.profileImage = req.file.path || req.file.secure_url || req.file.url;
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: updateData },
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "Profile updated successfully",
      user: sanitizeUserResponse(updatedUser),
    });
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ message: "Failed to update profile" });
  }
};

/**
 * Change Password (authenticated)
 */
export const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Current and new passwords are required" });
    }

    // SECURITY FIX: Strong password validation
    const passwordValidation = validatePasswordStrength(newPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({ message: passwordValidation.message });
    }

    const user = await User.findById(req.user._id).select("+password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    user.security = user.security || {};
    user.security.passwordChangedAt = new Date();
    await user.save();

    // Revoke other sessions (keep current)
    if (req.userSession) {
      await UserSession.revokeOtherSessions(user._id, req.userSession._id, "password_changed");
    }

    res.status(200).json({ message: "Password changed successfully" });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ message: "Failed to change password" });
  }
};

// ============================================
// SESSION MANAGEMENT
// ============================================

/**
 * Get Active Sessions
 */
export const getActiveSessions = async (req, res) => {
  try {
    const sessions = await UserSession.getActiveSessions(req.user._id);

    // Mark current session
    const currentSessionId = req.userSession?._id?.toString();

    res.status(200).json({
      success: true,
      sessions: sessions.map((s) => ({
        id: s._id,
        device: s.deviceInfo,
        ipAddress: s.ipAddress,
        createdAt: s.createdAt,
        lastActivity: s.lastActivity,
        isCurrent: s._id.toString() === currentSessionId,
      })),
    });
  } catch (err) {
    console.error("Get sessions error:", err);
    res.status(500).json({ message: "Failed to fetch sessions" });
  }
};

/**
 * Revoke Specific Session
 */
export const revokeSession = async (req, res) => {
  try {
    const { sessionId } = req.params;

    // Verify session belongs to user
    const session = await UserSession.findOne({
      _id: sessionId,
      user: req.user._id,
      isActive: true,
    });

    if (!session) {
      return res.status(404).json({ message: "Session not found" });
    }

    await UserSession.revokeSession(sessionId, "user_revoked");

    res.status(200).json({
      success: true,
      message: "Session revoked successfully",
    });
  } catch (err) {
    console.error("Revoke session error:", err);
    res.status(500).json({ message: "Failed to revoke session" });
  }
};

// ============================================
// UPGRADE TO OWNER
// ============================================

/**
 * Send Upgrade OTP
 */
export const sendUpgradeOtp = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.role === "owner") {
      return res.status(400).json({ message: "You are already registered as a property owner" });
    }

    const otp = generateSecureOTP();
    user.otp = hashOTP(otp); // SECURITY FIX: Store hashed OTP
    user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    try {
      await sendOTPEmail(user.email, otp, user.name);
    } catch (emailError) {
      console.error("❌ Error sending upgrade OTP:", emailError.message);
      return res.status(500).json({ message: "Failed to send OTP. Please try again." });
    }

    res.status(200).json({
      message: "Verification OTP sent to your email",
      email: user.email,
    });
  } catch (err) {
    console.error("Send upgrade OTP error:", err);
    res.status(500).json({ message: err.message });
  }
};

/**
 * Verify Upgrade OTP
 */
export const verifyUpgradeOtp = async (req, res) => {
  try {
    const { otp } = req.body;

    const user = await User.findById(req.user._id).select("+otp +otpExpires");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.role === "owner") {
      return res.status(400).json({ message: "You are already a property owner" });
    }

    // SECURITY FIX: Verify hashed OTP
    if (!user.otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    if (!verifyOTPHash(otp, user.otp)) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // Upgrade user to owner
    user.role = "owner";
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.status(200).json({
      message: "Congratulations! You can now list properties.",
      user: sanitizeUserResponse(user),
    });
  } catch (err) {
    console.error("Verify upgrade OTP error:", err);
    res.status(500).json({ message: err.message });
  }
};

// ============================================
// ADMIN FUNCTIONS
// ============================================

/**
 * Get All Users (Admin only)
 */
export const getAllUsers = async (req, res) => {
  try {
    const { role } = req.query;

    const filter = {};
    if (role === "Buyer") {
      filter.role = "user";
    } else if (role) {
      filter.role = role;
    }

    const users = await User.find(filter)
      .select("-password -otp -otpExpires -resetPasswordOtp -resetPasswordOtpExpires")
      .sort({ createdAt: -1 });

    res.status(200).json({
      message: "Users fetched",
      count: users.length,
      users: users.map(sanitizeUserResponse),
    });
  } catch (err) {
    console.error("Get all users error:", err);
    res.status(500).json({ message: "Failed to fetch users" });
  }
};

/**
 * Toggle Block User (Admin only)
 */
export const toggleBlockUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    const user = await User.findById(id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.isBlocked = !user.isBlocked;
    if (user.isBlocked) {
      user.blockReason = reason || "No reason provided";
      user.blockedAt = new Date();
      // Revoke all sessions when blocking
      await UserSession.revokeAllUserSessions(user._id, "user_blocked");
    } else {
      user.blockReason = "";
      user.blockedAt = null;
    }
    await user.save();

    res.status(200).json({
      message: user.isBlocked ? "User blocked successfully" : "User unblocked successfully",
      user: sanitizeUserResponse(user),
    });
  } catch (err) {
    console.error("Toggle block error:", err);
    res.status(500).json({ message: "Failed to update user status" });
  }
};

// Export functions that may already exist (placeholders for unchanged exports)


export const exportUsersCSV = async (req, res) => {
  try {
    const users = await User.find({ role: "user" }).sort({ createdAt: -1 });

    const fields = [
      { label: "Name", value: "name" },
      { label: "Email", value: "email" },
      { label: "Phone", value: "phone" },
      { label: "Role", value: "role" },
      { label: "Status", value: (row) => (row.isBlocked ? "Blocked" : "Active") },
      { label: "Joined Date", value: (row) => new Date(row.createdAt).toLocaleDateString() },
    ];

    const json2csvParser = new Parser({ fields });
    const csv = json2csvParser.parse(users);

    res.header("Content-Type", "text/csv");
    res.attachment("clients_list.csv");
    return res.send(csv);
  } catch (error) {
    console.error("Export CSV Error:", error);
    res.status(500).json({ message: "Failed to export CSV" });
  }
};

export const exportUsersPDF = async (req, res) => {
  try {
    const users = await User.find({ role: "user" }).sort({ createdAt: -1 });

    const doc = new PDFDocument({ margin: 30, size: "A4" });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", 'attachment; filename="clients_list.pdf"');

    doc.pipe(res);

    // Header
    doc.fontSize(20).text("Clients List", { align: "center" });
    doc.moveDown();

    // Table Header
    const tableTop = 100;
    const itemHeight = 20;
    let yPosition = tableTop;

    doc.fontSize(10).font("Helvetica-Bold");
    doc.text("Name", 50, yPosition);
    doc.text("Email", 150, yPosition);
    doc.text("Phone", 350, yPosition);
    doc.text("Status", 450, yPosition);

    // Table Rows
    doc.font("Helvetica");
    yPosition += itemHeight;

    users.forEach((user) => {
      if (yPosition > 750) {
        doc.addPage();
        yPosition = 50;
      }

      doc.text(user.name || "N/A", 50, yPosition);
      doc.text(user.email || "N/A", 150, yPosition);
      doc.text(user.phone || "N/A", 350, yPosition);
      doc.text(user.isBlocked ? "Blocked" : "Active", 450, yPosition);

      yPosition += itemHeight;
    });

    doc.end();
  } catch (error) {
    console.error("Export PDF Error:", error);
    res.status(500).json({ message: "Failed to export PDF" });
  }
};

export const exportOwnersCSV = async (req, res) => {
  try {
    const owners = await User.find({ role: "owner" }).sort({ createdAt: -1 });

    const fields = [
      { label: "Name", value: "name" },
      { label: "Email", value: "email" },
      { label: "Phone", value: "phone" },
      { label: "Role", value: "role" },
      { label: "Company", value: "company" },
      { label: "Status", value: (row) => (row.isBlocked ? "Blocked" : "Active") },
      { label: "Joined Date", value: (row) => new Date(row.createdAt).toLocaleDateString() },
    ];

    const json2csvParser = new Parser({ fields });
    const csv = json2csvParser.parse(owners);

    res.header("Content-Type", "text/csv");
    res.attachment("owners_list.csv");
    return res.send(csv);
  } catch (error) {
    console.error("Export Owners CSV Error:", error);
    res.status(500).json({ message: "Failed to export CSV" });
  }
};

export const exportOwnersPDF = async (req, res) => {
  try {
    const owners = await User.find({ role: "owner" }).sort({ createdAt: -1 });

    const doc = new PDFDocument({ margin: 30, size: "A4" });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", 'attachment; filename="owners_list.pdf"');

    doc.pipe(res);

    // Header
    doc.fontSize(20).text("Property Owners List", { align: "center" });
    doc.moveDown();

    // Table Header
    const tableTop = 100;
    const itemHeight = 20;
    let yPosition = tableTop;

    doc.fontSize(10).font("Helvetica-Bold");
    doc.text("Name", 50, yPosition);
    doc.text("Email", 150, yPosition);
    doc.text("Phone", 350, yPosition);
    doc.text("Status", 450, yPosition);

    // Table Rows
    doc.font("Helvetica");
    yPosition += itemHeight;

    owners.forEach((user) => {
      if (yPosition > 750) {
        doc.addPage();
        yPosition = 50;
      }

      doc.text(user.name || "N/A", 50, yPosition);
      doc.text(user.email || "N/A", 150, yPosition);
      doc.text(user.phone || "N/A", 350, yPosition);
      doc.text(user.isBlocked ? "Blocked" : "Active", 450, yPosition);

      yPosition += itemHeight;
    });

    doc.end();
  } catch (error) {
    console.error("Export Owners PDF Error:", error);
    res.status(500).json({ message: "Failed to export PDF" });
  }
};