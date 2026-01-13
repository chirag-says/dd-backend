import mongoose from "mongoose";

/**
 * Enterprise Role Schema
 * Defines roles with hierarchical permissions for RBAC
 */
const roleSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: [true, "Role name is required"],
            unique: true,
            trim: true,
            enum: ["super_admin", "admin", "manager", "viewer"],
        },
        displayName: {
            type: String,
            required: true,
        },
        description: {
            type: String,
            default: "",
        },
        // Hierarchy level - higher number = more privileges
        level: {
            type: Number,
            required: true,
            min: 0,
            max: 100,
        },
        // Permissions assigned to this role
        permissions: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Permission",
            },
        ],
        // Whether users with this role can create/manage other admins
        canManageAdmins: {
            type: Boolean,
            default: false,
        },
        // Whether this role is a system role (cannot be deleted)
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

// Index for faster lookups
roleSchema.index({ name: 1 });
roleSchema.index({ level: -1 });

// Virtual to get permission names
roleSchema.virtual("permissionNames", {
    ref: "Permission",
    localField: "permissions",
    foreignField: "_id",
});

export default mongoose.model("Role", roleSchema);
