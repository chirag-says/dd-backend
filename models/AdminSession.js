import mongoose from "mongoose";
import crypto from "crypto";

/**
 * AdminSession Schema
 * Server-side session management for enterprise security
 * Enables session revocation, integrity verification, and audit trails
 * 
 * SECURITY FEATURES:
 * - Lenient fingerprint validation with User-Agent + truncated IP range
 * - OS change detection for session revocation
 * - Browser version tolerance for minor updates
 */
const adminSessionSchema = new mongoose.Schema(
    {
        // Reference to the admin user
        admin: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Admin",
            required: true,
            index: true,
        },
        // Unique session token (stored in HttpOnly cookie)
        sessionToken: {
            type: String,
            required: true,
            unique: true,
            index: true,
        },
        // Session fingerprint for integrity verification
        fingerprint: {
            type: String,
            required: true,
        },
        // ============================================
        // SECURITY: Extended fingerprint data for lenient validation
        // Stores parsed components for intelligent comparison
        // ============================================
        fingerprintData: {
            userAgent: { type: String, default: "" },
            os: { type: String, default: "" },           // Operating system family
            browser: { type: String, default: "" },      // Browser family (not version)
            ipPrefix: { type: String, default: "" },     // Truncated IP (first 3 octets for IPv4)
            device: { type: String, default: "" },       // Device type (Desktop/Mobile/Tablet)
        },
        // IP address of session creation
        ipAddress: {
            type: String,
            required: true,
        },
        // User agent at session creation
        userAgent: {
            type: String,
            default: "",
        },
        // Session expiration time
        expiresAt: {
            type: Date,
            required: true,
            index: true,
        },
        // Last activity timestamp for session timeout
        lastActivity: {
            type: Date,
            default: Date.now,
        },
        // Whether MFA was verified for this session
        mfaVerified: {
            type: Boolean,
            default: false,
        },
        // SECURITY FIX: Track if MFA setup is pending
        // When true, admin can only access MFA setup endpoints
        mfaSetupPending: {
            type: Boolean,
            default: false,
        },
        // Session status
        isActive: {
            type: Boolean,
            default: true,
            index: true,
        },
        // Revocation details
        revokedAt: {
            type: Date,
            default: null,
        },
        revokedReason: {
            type: String,
            default: null,
        },
        // Device/location info for security
        deviceInfo: {
            browser: String,
            os: String,
            device: String,
        },
    },
    { timestamps: true }
);

// Compound index for efficient session lookups
adminSessionSchema.index({ admin: 1, isActive: 1 });
adminSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL index

/**
 * Generate a cryptographically secure session token
 */
adminSessionSchema.statics.generateToken = function () {
    return crypto.randomBytes(64).toString("hex");
};

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

    if (userAgent.includes("Mobile") || userAgent.includes("Android") && !userAgent.includes("Tablet")) return "Mobile";
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

/**
 * Generate session fingerprint from request data
 * SECURITY: Creates both a hash and parsed data for lenient validation
 */
adminSessionSchema.statics.generateFingerprint = function (req) {
    const userAgent = req.headers["user-agent"] || "";
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
        req.headers["x-real-ip"] ||
        req.connection?.remoteAddress ||
        req.ip || "unknown";

    // Create fingerprint hash for quick comparison
    const data = [
        userAgent,
        getTruncatedIpPrefix(ip),
    ].join("|");

    return crypto.createHash("sha256").update(data).digest("hex");
};

/**
 * Generate extended fingerprint data for lenient validation
 */
adminSessionSchema.statics.generateFingerprintData = function (req) {
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
 * Verify session fingerprint matches current request
 * Simple hash-based comparison
 */
adminSessionSchema.methods.verifyFingerprint = function (req) {
    const currentFingerprint = this.constructor.generateFingerprint(req);
    return this.fingerprint === currentFingerprint;
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
adminSessionSchema.methods.validateFingerprintLenient = function (req) {
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
    // (e.g., user might switch between Chrome and Chrome Canary)
    if (storedData.browser && currentData.browser !== storedData.browser) {
        console.warn(`[AUTH] Browser family changed from ${storedData.browser} to ${currentData.browser} - allowing but flagging`);
        needsRefresh = true;
    }

    // User-Agent string variations (browser updates, patches)
    if (storedData.userAgent && currentData.userAgent !== storedData.userAgent) {
        // As long as OS, device, and browser family match, this is acceptable
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
 * SECURITY FIX: Production-Ready Session Binding Validation
 * 
 * This method implements BALANCED session validation that:
 * 1. ALLOWS IP changes within the same subnet (first 3 octets for IPv4)
 *    - Rationale: Mobile networks, DHCP, and corporate proxies often change last octet
 * 2. REJECTS User-Agent changes strictly (browser fingerprint must match)
 *    - Rationale: UA changes mid-session indicate potential session hijacking
 * 3. REJECTS OS or device type changes (major anomaly detection)
 * 
 * This balances security against usability for admins on dynamic networks.
 * 
 * Returns: { valid: boolean, reason?: string }
 */
adminSessionSchema.methods.validateFingerprintStrict = function (req) {
    // Get current IP address
    const currentIp = req.ip ||
        req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
        req.headers["x-real-ip"] ||
        req.connection?.remoteAddress ||
        "unknown";

    // Get current User-Agent
    const currentUserAgent = req.headers["user-agent"] || "";

    // Stored values
    const storedIp = this.ipAddress || "";
    const storedUserAgent = this.userAgent || "";

    // ============================================
    // CHECK 1: User-Agent MUST match exactly
    // This is the primary defense against session hijacking
    // ============================================
    if (storedUserAgent && currentUserAgent !== storedUserAgent) {
        console.warn(`[AUTH] STRICT: User-Agent changed - potential session hijacking`);
        return {
            valid: false,
            reason: "Session verification failed: Browser fingerprint changed",
        };
    }

    // ============================================
    // CHECK 2: IP Subnet Validation (Relaxed for usability)
    // Allow same-subnet changes (last octet can differ)
    // This handles DHCP lease changes, mobile network hopping
    // ============================================
    if (storedIp && currentIp) {
        const storedPrefix = getTruncatedIpPrefix(storedIp);
        const currentPrefix = getTruncatedIpPrefix(currentIp);

        if (storedPrefix && currentPrefix && storedPrefix !== currentPrefix) {
            // Different subnet = suspicious
            console.warn(`[AUTH] STRICT: IP subnet changed from ${storedPrefix}.x to ${currentPrefix}.x`);
            return {
                valid: false,
                reason: "Session verification failed: Network location changed significantly",
            };
        }
        // Same subnet with different last octet = OK (log but allow)
        if (storedIp !== currentIp) {
            console.log(`[AUTH] INFO: IP changed within same subnet (${storedIp} -> ${currentIp}) - allowed`);
        }
    }

    // ============================================
    // CHECK 3: OS and Device Type (from fingerprintData)
    // Major anomaly = immediate revocation
    // ============================================
    if (this.fingerprintData) {
        const currentOs = extractOsFamily(currentUserAgent);
        const currentDevice = extractDeviceType(currentUserAgent);

        // OS change = definite hijack attempt
        if (this.fingerprintData.os && currentOs !== this.fingerprintData.os &&
            this.fingerprintData.os !== "Unknown" && currentOs !== "Unknown") {
            console.warn(`[AUTH] STRICT: OS changed from ${this.fingerprintData.os} to ${currentOs}`);
            return {
                valid: false,
                reason: "Session verification failed: Operating system changed",
            };
        }

        // Device type change (Desktop ↔ Mobile) = suspicious
        if (this.fingerprintData.device && currentDevice !== this.fingerprintData.device &&
            this.fingerprintData.device !== "Unknown" && currentDevice !== "Unknown") {
            console.warn(`[AUTH] STRICT: Device type changed from ${this.fingerprintData.device} to ${currentDevice}`);
            return {
                valid: false,
                reason: "Session verification failed: Device type changed",
            };
        }
    }

    return { valid: true };
};

/**
 * Extend session activity
 */
adminSessionSchema.methods.touch = async function () {
    this.lastActivity = new Date();
    return this.save();
};

/**
 * Revoke session
 */
adminSessionSchema.methods.revoke = async function (reason = "manual_logout") {
    this.isActive = false;
    this.revokedAt = new Date();
    this.revokedReason = reason;
    return this.save();
};

/**
 * Revoke all sessions for an admin (except current)
 */
adminSessionSchema.statics.revokeAllForAdmin = async function (
    adminId,
    exceptSessionId = null,
    reason = "security_action"
) {
    const query = { admin: adminId, isActive: true };
    if (exceptSessionId) {
        query._id = { $ne: exceptSessionId };
    }
    return this.updateMany(query, {
        isActive: false,
        revokedAt: new Date(),
        revokedReason: reason,
    });
};

/**
 * Clean up expired sessions
 */
adminSessionSchema.statics.cleanupExpired = async function () {
    return this.deleteMany({
        $or: [{ expiresAt: { $lt: new Date() } }, { isActive: false }],
    });
};

// ============================================
// MIDDLEWARE: Auto-populate fingerprintData on save
// ============================================
adminSessionSchema.pre("save", function (next) {
    // If this is a new session and fingerprintData is empty, generate it
    if (this.isNew && (!this.fingerprintData || !this.fingerprintData.os)) {
        // We can't access req here, so fingerprintData should be set explicitly
        // during session creation. This is a fallback.
        if (this.userAgent) {
            this.fingerprintData = {
                userAgent: this.userAgent.substring(0, 512),
                os: extractOsFamily(this.userAgent),
                browser: extractBrowserFamily(this.userAgent),
                ipPrefix: getTruncatedIpPrefix(this.ipAddress),
                device: extractDeviceType(this.userAgent),
            };
        }
    }
    next();
});

export default mongoose.model("AdminSession", adminSessionSchema);
