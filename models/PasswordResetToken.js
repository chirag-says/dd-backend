/**
 * Password Reset Token Model
 * Cryptographically secure, single-use, time-limited tokens for password reset
 */
import mongoose from "mongoose";
import crypto from "crypto";

const passwordResetTokenSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },
        // Hashed token (raw token sent to user via email)
        tokenHash: {
            type: String,
            required: true,
            unique: true,
        },
        // Token expiration (15 minutes)
        expiresAt: {
            type: Date,
            required: true,
            index: { expireAfterSeconds: 0 }, // TTL index - auto-delete expired tokens
        },
        // Track usage
        isUsed: {
            type: Boolean,
            default: false,
        },
        usedAt: {
            type: Date,
            default: null,
        },
        // Security tracking
        requestedFromIp: {
            type: String,
            required: true,
        },
        usedFromIp: {
            type: String,
            default: null,
        },
        // Rate limiting - track attempts
        verificationAttempts: {
            type: Number,
            default: 0,
        },
    },
    { timestamps: true }
);

// Index for cleanup and validation
passwordResetTokenSchema.index({ user: 1, isUsed: 1 });

/**
 * Generate a cryptographically secure reset token
 * Returns { token, tokenHash }
 */
passwordResetTokenSchema.statics.generateToken = function () {
    // Generate 32 bytes of random data
    const rawToken = crypto.randomBytes(32).toString("hex");

    // Hash the token for storage
    const tokenHash = crypto
        .createHash("sha256")
        .update(rawToken)
        .digest("hex");

    return { rawToken, tokenHash };
};

/**
 * Hash a token for comparison
 */
passwordResetTokenSchema.statics.hashToken = function (token) {
    return crypto.createHash("sha256").update(token).digest("hex");
};

/**
 * Create a new password reset token
 */
passwordResetTokenSchema.statics.createResetToken = async function (userId, ip) {
    // Invalidate any existing tokens for this user
    await this.invalidateUserTokens(userId);

    const { rawToken, tokenHash } = this.generateToken();

    // Token valid for 15 minutes
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await this.create({
        user: userId,
        tokenHash,
        expiresAt,
        requestedFromIp: ip,
    });

    return rawToken; // Return raw token (to send via email)
};

/**
 * Validate a reset token
 * Returns user document if valid, null otherwise
 */
passwordResetTokenSchema.statics.validateToken = async function (rawToken, ip) {
    const tokenHash = this.hashToken(rawToken);

    const resetToken = await this.findOne({
        tokenHash,
        isUsed: false,
        expiresAt: { $gt: new Date() },
    }).populate("user", "-password");

    if (!resetToken) {
        return null;
    }

    // Track verification attempt
    resetToken.verificationAttempts += 1;

    // Rate limit: max 5 attempts
    if (resetToken.verificationAttempts > 5) {
        resetToken.isUsed = true; // Invalidate token
        await resetToken.save();
        return null;
    }

    await resetToken.save();

    return resetToken;
};

/**
 * Mark token as used
 */
passwordResetTokenSchema.statics.useToken = async function (tokenHash, ip) {
    return this.findOneAndUpdate(
        { tokenHash, isUsed: false },
        {
            isUsed: true,
            usedAt: new Date(),
            usedFromIp: ip,
        }
    );
};

/**
 * Invalidate all tokens for a user
 */
passwordResetTokenSchema.statics.invalidateUserTokens = async function (userId) {
    return this.updateMany(
        { user: userId, isUsed: false },
        { isUsed: true, usedAt: new Date() }
    );
};

/**
 * Check rate limiting for password reset requests
 * Limit: 3 requests per hour
 */
passwordResetTokenSchema.statics.checkRateLimit = async function (userId) {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

    const recentRequests = await this.countDocuments({
        user: userId,
        createdAt: { $gte: oneHourAgo },
    });

    return recentRequests < 3;
};

/**
 * Cleanup old tokens
 */
passwordResetTokenSchema.statics.cleanup = async function () {
    const result = await this.deleteMany({
        $or: [
            { expiresAt: { $lt: new Date() } },
            { isUsed: true, updatedAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } },
        ],
    });
    return result.deletedCount;
};

export default mongoose.model("PasswordResetToken", passwordResetTokenSchema);
