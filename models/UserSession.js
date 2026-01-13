/**
 * User Session Model
 * Enterprise-grade server-side session management for end users
 * 
 * SECURITY FEATURES:
 * - Lenient fingerprint validation with User-Agent + truncated IP range
 * - OS change detection for session revocation
 * - Browser version tolerance for minor updates
 */
import mongoose from "mongoose";
import crypto from "crypto";

// ============================================
// SECURITY: Fingerprint parsing utilities
// ============================================

/**
 * Extract OS family from User-Agent string
 * SECURITY: Used for major anomaly detection
 */
const extractOsFamily = (userAgent) => {
    if (!userAgent) return "Unknown";

    if (userAgent.includes("Windows NT 10")) return "Windows10";
    if (userAgent.includes("Windows NT 6.3")) return "Windows8.1";
    if (userAgent.includes("Windows NT 6.2")) return "Windows8";
    if (userAgent.includes("Windows NT 6.1")) return "Windows7";
    if (userAgent.includes("Windows")) return "Windows";
    if (userAgent.includes("Mac OS X")) return "macOS";
    if (userAgent.includes("Android")) return "Android";
    if (userAgent.includes("iPhone") || userAgent.includes("iPad")) return "iOS";
    if (userAgent.includes("Linux")) return "Linux";
    if (userAgent.includes("CrOS")) return "ChromeOS";

    return "Unknown";
};

/**
 * Extract browser family from User-Agent string
 * SECURITY: Used for browser family matching (ignores version for lenient validation)
 */
const extractBrowserFamily = (userAgent) => {
    if (!userAgent) return "Unknown";

    // Order matters - check more specific patterns first
    if (userAgent.includes("Edg/")) return "Edge";
    if (userAgent.includes("OPR/") || userAgent.includes("Opera")) return "Opera";
    if (userAgent.includes("Chrome/")) return "Chrome";
    if (userAgent.includes("Firefox/")) return "Firefox";
    if (userAgent.includes("Safari/") && !userAgent.includes("Chrome")) return "Safari";
    if (userAgent.includes("Trident/") || userAgent.includes("MSIE")) return "IE";

    return "Unknown";
};

/**
 * Extract device type from User-Agent string
 */
const extractDeviceType = (userAgent) => {
    if (!userAgent) return "Unknown";

    if (userAgent.includes("Mobile") || (userAgent.includes("Android") && !userAgent.includes("Tablet"))) return "Mobile";
    if (userAgent.includes("Tablet") || userAgent.includes("iPad")) return "Tablet";

    return "Desktop";
};

/**
 * Get truncated IP prefix for lenient comparison
 * SECURITY: Compares first 3 octets for IPv4, or first 4 groups for IPv6
 * This allows for DHCP lease changes within the same network
 */
const getTruncatedIpPrefix = (ip) => {
    if (!ip || ip === "unknown") return "";

    // Handle IPv4
    if (ip.includes(".")) {
        const parts = ip.split(".");
        if (parts.length >= 3) {
            return parts.slice(0, 3).join(".");
        }
    }

    // Handle IPv6 (take first 4 groups)
    if (ip.includes(":")) {
        const parts = ip.split(":");
        if (parts.length >= 4) {
            return parts.slice(0, 4).join(":");
        }
    }

    return ip;
};

const userSessionSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },
        // Secure session token (stored hashed in DB)
        sessionToken: {
            type: String,
            required: true,
            unique: true,
            index: true,
        },
        // Token hash for validation
        tokenHash: {
            type: String,
            required: true,
        },
        // Session fingerprint for integrity check
        fingerprint: {
            type: String,
            required: true,
        },
        // ============================================
        // SECURITY: Extended fingerprint data for lenient validation
        // ============================================
        fingerprintData: {
            userAgent: { type: String, default: "" },
            os: { type: String, default: "" },           // Operating system family
            browser: { type: String, default: "" },      // Browser family (not version)
            ipPrefix: { type: String, default: "" },     // Truncated IP (first 3 octets for IPv4)
            device: { type: String, default: "" },       // Device type (Desktop/Mobile/Tablet)
        },
        // Device and client information
        deviceInfo: {
            userAgent: String,
            platform: String,
            browser: String,
            isMobile: Boolean,
        },
        // Network information
        ipAddress: {
            type: String,
            required: true,
        },
        // Session expiration
        expiresAt: {
            type: Date,
            required: true,
            index: { expireAfterSeconds: 0 }, // TTL index - auto-delete expired sessions
        },
        // Session state
        isActive: {
            type: Boolean,
            default: true,
        },
        // Revocation tracking
        revokedAt: {
            type: Date,
            default: null,
        },
        revokedReason: {
            type: String,
            default: null,
        },
        // Activity tracking
        lastActivity: {
            type: Date,
            default: Date.now,
        },
    },
    { timestamps: true }
);

// Indexes for efficient queries
userSessionSchema.index({ user: 1, isActive: 1 });
userSessionSchema.index({ tokenHash: 1 });
userSessionSchema.index({ expiresAt: 1 });

/**
 * Generate a cryptographically secure session token
 */
userSessionSchema.statics.generateSessionToken = function () {
    return crypto.randomBytes(48).toString("base64url");
};

/**
 * Hash a session token for storage
 */
userSessionSchema.statics.hashToken = function (token) {
    return crypto.createHash("sha256").update(token).digest("hex");
};

/**
 * Generate session fingerprint from request
 * SECURITY: Uses User-Agent and truncated IP for stable fingerprinting
 */
userSessionSchema.statics.generateFingerprint = function (req) {
    const userAgent = req.headers["user-agent"] || "unknown";
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
        req.headers["x-real-ip"] ||
        req.connection?.remoteAddress ||
        req.ip || "unknown";

    // Only use User-Agent and truncated IP for fingerprinting
    const components = [
        userAgent,
        getTruncatedIpPrefix(ip),
    ].join("|");

    return crypto.createHash("sha256").update(components).digest("hex").substring(0, 32);
};

/**
 * Generate extended fingerprint data for lenient validation
 */
userSessionSchema.statics.generateFingerprintData = function (req) {
    const userAgent = req.headers["user-agent"] || "";
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
        req.headers["x-real-ip"] ||
        req.connection?.remoteAddress ||
        req.ip || "unknown";

    return {
        userAgent: userAgent.substring(0, 512),
        os: extractOsFamily(userAgent),
        browser: extractBrowserFamily(userAgent),
        ipPrefix: getTruncatedIpPrefix(ip),
        device: extractDeviceType(userAgent),
    };
};

/**
 * Create a new session for user
 */
userSessionSchema.statics.createSession = async function (user, req, expirationHours = 168) {
    // 7 days default
    const sessionToken = this.generateSessionToken();
    const tokenHash = this.hashToken(sessionToken);
    const fingerprint = this.generateFingerprint(req);
    const fingerprintData = this.generateFingerprintData(req);
    const expiresAt = new Date(Date.now() + expirationHours * 60 * 60 * 1000);

    // Parse user agent
    const userAgent = req.headers["user-agent"] || "";
    const isMobile = /mobile|android|iphone|ipad/i.test(userAgent);
    const platform = extractOsFamily(userAgent);

    const session = await this.create({
        user: user._id,
        sessionToken: tokenHash, // Store hash, not raw token
        tokenHash,
        fingerprint,
        fingerprintData, // Store parsed data for lenient validation
        deviceInfo: {
            userAgent: userAgent.substring(0, 512), // Limit length
            platform,
            isMobile,
            browser: extractBrowserFamily(userAgent),
        },
        ipAddress: req.ip || req.connection?.remoteAddress || "unknown",
        expiresAt,
        lastActivity: new Date(),
    });

    return { session, sessionToken }; // Return raw token (for cookie) and session
};

/**
 * SECURITY: Lenient fingerprint validation
 * 
 * This method implements intelligent session validation that:
 * 1. ALLOWS minor changes (browser version updates, slight UA variations)
 * 2. REVOKES on major anomalies (OS change, IP range change, device type change)
 * 3. REFRESHES fingerprint on acceptable minor changes
 * 
 * Returns: { valid: boolean, refreshed: boolean, reason?: string }
 */
userSessionSchema.methods.validateFingerprintLenient = function (req) {
    const currentData = this.constructor.generateFingerprintData(req);
    const storedData = this.fingerprintData || {};

    // ============================================
    // MAJOR ANOMALY CHECKS - Revoke session immediately
    // ============================================

    // 1. Operating System change = REVOKE
    // Rationale: A user's OS doesn't change mid-session; this indicates session hijacking
    if (storedData.os && currentData.os !== storedData.os &&
        storedData.os !== "Unknown" && currentData.os !== "Unknown") {
        return {
            valid: false,
            refreshed: false,
            reason: `OS changed from ${storedData.os} to ${currentData.os}`,
        };
    }

    // 2. Device type change = REVOKE
    // Rationale: Desktop → Mobile or vice versa is suspicious
    if (storedData.device && currentData.device !== storedData.device &&
        storedData.device !== "Unknown" && currentData.device !== "Unknown") {
        return {
            valid: false,
            refreshed: false,
            reason: `Device type changed from ${storedData.device} to ${currentData.device}`,
        };
    }

    // 3. IP prefix change (different network) = REVOKE
    // Rationale: User shouldn't jump between completely different IP ranges
    // This catches country/ISP changes while allowing DHCP within same network
    if (storedData.ipPrefix && currentData.ipPrefix &&
        storedData.ipPrefix !== currentData.ipPrefix) {
        return {
            valid: false,
            refreshed: false,
            reason: `IP range changed from ${storedData.ipPrefix}.x to ${currentData.ipPrefix}.x`,
        };
    }

    // ============================================
    // MINOR CHANGES - Allow and optionally refresh
    // ============================================

    let needsRefresh = false;

    // Browser family change is suspicious but allowed with warning
    if (storedData.browser && currentData.browser !== storedData.browser) {
        console.warn(`[Auth] Browser family changed from ${storedData.browser} to ${currentData.browser} - allowing but flagging`);
        needsRefresh = true;
    }

    // User-Agent string variations (browser updates, patches)
    if (storedData.userAgent && currentData.userAgent !== storedData.userAgent) {
        needsRefresh = true;
    }

    // Refresh fingerprint data if minor changes detected
    if (needsRefresh) {
        this.fingerprintData = currentData;
        this.fingerprint = this.constructor.generateFingerprint(req);
        // Note: Caller must save the session
    }

    return {
        valid: true,
        refreshed: needsRefresh,
    };
};

/**
 * Validate session token and return session
 * SECURITY: Now uses lenient fingerprint validation
 */
userSessionSchema.statics.validateSession = async function (sessionToken, req) {
    if (!sessionToken) return null;

    const tokenHash = this.hashToken(sessionToken);
    const session = await this.findOne({
        tokenHash,
        isActive: true,
        expiresAt: { $gt: new Date() },
    }).populate("user", "-password -otp -otpExpires -resetPasswordOtp -resetPasswordOtpExpires");

    if (!session) return null;

    // ============================================
    // SECURITY: Lenient fingerprint validation
    // Revokes on major anomalies, refreshes on minor changes
    // ============================================
    const validation = session.validateFingerprintLenient(req);

    if (!validation.valid) {
        console.warn(`[Auth] Session revoked for user ${session.user?._id}: ${validation.reason}`);
        await this.revokeSession(session._id, `fingerprint_anomaly: ${validation.reason}`);
        return null;
    }

    // Update last activity and save (including any fingerprint refresh)
    session.lastActivity = new Date();
    await session.save();

    return session;
};

/**
 * Revoke a specific session
 */
userSessionSchema.statics.revokeSession = async function (sessionId, reason = "manual_logout") {
    return this.findByIdAndUpdate(sessionId, {
        isActive: false,
        revokedAt: new Date(),
        revokedReason: reason,
    });
};

/**
 * Revoke all sessions for a user
 */
userSessionSchema.statics.revokeAllUserSessions = async function (userId, reason = "logout_all") {
    return this.updateMany(
        { user: userId, isActive: true },
        {
            isActive: false,
            revokedAt: new Date(),
            revokedReason: reason,
        }
    );
};

/**
 * Revoke all sessions except current
 */
userSessionSchema.statics.revokeOtherSessions = async function (userId, currentSessionId, reason = "security") {
    return this.updateMany(
        {
            user: userId,
            _id: { $ne: currentSessionId },
            isActive: true,
        },
        {
            isActive: false,
            revokedAt: new Date(),
            revokedReason: reason,
        }
    );
};

/**
 * Get active sessions for user
 */
userSessionSchema.statics.getActiveSessions = async function (userId) {
    return this.find({
        user: userId,
        isActive: true,
        expiresAt: { $gt: new Date() },
    })
        .select("deviceInfo ipAddress createdAt lastActivity fingerprintData")
        .sort({ lastActivity: -1 });
};

/**
 * Cleanup expired sessions
 */
userSessionSchema.statics.cleanupExpiredSessions = async function () {
    const result = await this.deleteMany({
        $or: [
            { expiresAt: { $lt: new Date() } },
            { isActive: false, updatedAt: { $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }
        ],
    });
    return result.deletedCount;
};

export default mongoose.model("UserSession", userSessionSchema);
