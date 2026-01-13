import mongoose from "mongoose";

const reportSchema = new mongoose.Schema(
    {
        reportedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
        },
        // Context can be a chat message or a property listing
        contextType: {
            type: String,
            enum: ["message", "property"],
            default: "message",
        },
        message: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Message",
        },
        conversation: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Conversation",
        },
        property: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Property",
        },
        reason: {
            type: String,
            required: true,
            trim: true,
        },
        status: {
            type: String,
            enum: ["pending", "reviewed", "resolved", "dismissed"],
            default: "pending",
        },
        adminNotes: {
            type: String,
        },
        reviewedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Admin",
        },
        reviewedAt: {
            type: Date,
        },
    },
    { timestamps: true }
);

// Index for easy lookup
reportSchema.index({ status: 1 });
reportSchema.index({ createdAt: -1 });
reportSchema.index({ contextType: 1 });

const Report = mongoose.model("Report", reportSchema);
export default Report;
