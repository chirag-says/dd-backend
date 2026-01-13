import mongoose from "mongoose";

/**
 * AuditLog Schema
 * Comprehensive logging of all administrative actions for security and compliance
 */
const auditLogSchema = new mongoose.Schema(
    {
        // Who performed the action (null for failed login attempts where user doesn't exist)
        admin: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Admin",
            required: false, // Made optional for failed logins where admin doesn't exist
            index: true,
            default: null,
        },
        // Admin snapshot at time of action (in case admin is deleted later)
        adminSnapshot: {
            name: String,
            email: String,
            role: String,
        },
        // Action category
        category: {
            type: String,
            required: true,
            enum: [
                "authentication",
                "authorization",
                "admin_management",
                "user_management",
                "property_management",
                "lead_management",
                "report_management",
                "settings",
                "security",
                "data_access",
                "system",
            ],
            index: true,
        },
        // Specific action performed
        action: {
            type: String,
            required: true,
            index: true,
        },
        // Resource type being accessed/modified
        resourceType: {
            type: String,
            default: null,
        },
        // Resource ID being accessed/modified
        resourceId: {
            type: mongoose.Schema.Types.Mixed,
            default: null,
        },
        // Detailed description of the action
        description: {
            type: String,
            required: true,
        },
        // Request details
        request: {
            method: String,
            path: String,
            query: mongoose.Schema.Types.Mixed,
            body: mongoose.Schema.Types.Mixed, // Sanitized - no passwords
        },
        // Client information
        client: {
            ipAddress: {
                type: String,
                required: true,
                index: true,
            },
            userAgent: String,
            origin: String,
            referer: String,
        },
        // Session information
        sessionId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "AdminSession",
            default: null,
        },
        // Result of the action
        result: {
            type: String,
            enum: ["success", "failure", "partial", "denied"],
            required: true,
            index: true,
        },
        // Error details if action failed
        error: {
            code: String,
            message: String,
            stack: String,
        },
        // Response status code
        statusCode: {
            type: Number,
            default: null,
        },
        // Duration of the operation in milliseconds
        duration: {
            type: Number,
            default: null,
        },
        // Before/after state for change tracking
        changes: {
            before: mongoose.Schema.Types.Mixed,
            after: mongoose.Schema.Types.Mixed,
        },
        // Additional metadata
        metadata: {
            type: mongoose.Schema.Types.Mixed,
            default: {},
        },
        // Severity level
        severity: {
            type: String,
            enum: ["low", "medium", "high", "critical"],
            default: "low",
        },
        // Flag for security-related events
        isSecurityEvent: {
            type: Boolean,
            default: false,
            index: true,
        },
    },
    {
        timestamps: true,
    }
);

// Compound indexes for common query patterns
auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ admin: 1, createdAt: -1 });
auditLogSchema.index({ category: 1, action: 1, createdAt: -1 });
auditLogSchema.index({ "client.ipAddress": 1, createdAt: -1 });
auditLogSchema.index({ isSecurityEvent: 1, createdAt: -1 });

/**
 * Static method to create an audit log entry
 */
auditLogSchema.statics.log = async function ({
    admin,
    adminSnapshot,
    category,
    action,
    resourceType = null,
    resourceId = null,
    description,
    req = null,
    sessionId = null,
    result = "success",
    error = null,
    statusCode = null,
    duration = null,
    changes = null,
    metadata = {},
    severity = "low",
    isSecurityEvent = false,
}) {
    // Sanitize request body (remove sensitive fields)
    let sanitizedBody = null;
    if (req?.body) {
        const { password, currentPassword, newPassword, confirmPassword, otp, mfaCode, ...safe } =
            req.body;
        sanitizedBody = Object.keys(safe).length > 0 ? safe : null;
    }

    const entry = {
        admin: admin?._id || admin,
        adminSnapshot: adminSnapshot || {
            name: admin?.name,
            email: admin?.email,
            role: admin?.role?.name || admin?.role,
        },
        category,
        action,
        resourceType,
        resourceId,
        description,
        request: req
            ? {
                method: req.method,
                path: req.originalUrl || req.path,
                query: Object.keys(req.query || {}).length > 0 ? req.query : null,
                body: sanitizedBody,
            }
            : null,
        client: req
            ? {
                ipAddress: req.ip || req.connection?.remoteAddress || "unknown",
                userAgent: req.headers?.["user-agent"] || null,
                origin: req.headers?.origin || null,
                referer: req.headers?.referer || null,
            }
            : { ipAddress: "system" },
        sessionId,
        result,
        error: error
            ? {
                code: error.code || error.name,
                message: error.message,
                stack: process.env.NODE_ENV === "development" ? error.stack : null,
            }
            : null,
        statusCode,
        duration,
        changes,
        metadata,
        severity,
        isSecurityEvent,
    };

    try {
        return await this.create(entry);
    } catch (err) {
        // Don't let audit logging failures break the application
        console.error("Audit log error:", err.message);
        return null;
    }
};

/**
 * Log authentication events
 */
auditLogSchema.statics.logAuth = async function (admin, action, req, result, error = null) {
    const severity = result === "failure" ? "high" : "low";
    const isSecurityEvent = ["login_failed", "mfa_failed", "session_hijack_attempt"].includes(action);

    return this.log({
        admin,
        category: "authentication",
        action,
        description: `Authentication action: ${action}`,
        req,
        result,
        error,
        severity,
        isSecurityEvent,
    });
};

/**
 * Log authorization events
 */
auditLogSchema.statics.logAccess = async function (
    admin,
    resourceType,
    resourceId,
    action,
    req,
    result
) {
    return this.log({
        admin,
        category: "data_access",
        action,
        resourceType,
        resourceId,
        description: `Accessed ${resourceType}: ${action}`,
        req,
        result,
    });
};

export default mongoose.model("AuditLog", auditLogSchema);
