import mongoose from "mongoose";

/**
 * Permission Schema
 * Granular, resource-based permissions for fine-grained access control
 */
const permissionSchema = new mongoose.Schema(
    {
        // Unique permission code (e.g., "users:read", "properties:delete")
        code: {
            type: String,
            required: [true, "Permission code is required"],
            unique: true,
            trim: true,
            match: [/^[a-z_]+:[a-z_]+$/, "Permission code must be in format 'resource:action'"],
        },
        // Human-readable name
        name: {
            type: String,
            required: true,
        },
        // Description of what this permission allows
        description: {
            type: String,
            default: "",
        },
        // Resource this permission applies to
        resource: {
            type: String,
            required: true,
            enum: [
                "dashboard",
                "users",
                "admins",
                "properties",
                "leads",
                "reports",
                "categories",
                "settings",
                "audit_logs",
                "analytics",
                "messages",
                "notifications",
            ],
            index: true,
        },
        // Action this permission allows
        action: {
            type: String,
            required: true,
            enum: ["create", "read", "update", "delete", "manage", "export", "approve", "reject"],
            index: true,
        },
        // Whether this is a system permission (cannot be deleted)
        isSystem: {
            type: Boolean,
            default: false,
        },
        isActive: {
            type: Boolean,
            default: true,
        },
    },
    { timestamps: true }
);

// Compound index for resource:action lookups
permissionSchema.index({ resource: 1, action: 1 }, { unique: true });

/**
 * Generate permission code from resource and action
 */
permissionSchema.pre("validate", function (next) {
    if (this.resource && this.action && !this.code) {
        this.code = `${this.resource}:${this.action}`;
    }
    next();
});

/**
 * Get all permissions for a resource
 */
permissionSchema.statics.getForResource = async function (resource) {
    return this.find({ resource, isActive: true });
};

/**
 * Check if a permission code exists
 */
permissionSchema.statics.exists = async function (code) {
    return !!(await this.findOne({ code, isActive: true }));
};

export default mongoose.model("Permission", permissionSchema);
