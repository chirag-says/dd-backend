import mongoose from "mongoose";

const contactInquirySchema = new mongoose.Schema(
  {
    // User who sent the inquiry (must be logged in)
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    
    // Snapshot of user info at time of inquiry
    userSnapshot: {
      name: { type: String, required: true },
      email: { type: String, required: true },
      phone: { type: String },
      profileImage: { type: String },
    },
    
    // Inquiry details
    subject: {
      type: String,
      required: true,
      trim: true,
    },
    
    message: {
      type: String,
      required: true,
      trim: true,
    },
    
    // Inquiry type/category
    category: {
      type: String,
      enum: ["general", "property", "partnership", "support", "feedback", "complaint", "other"],
      default: "general",
    },
    
    // Admin response
    status: {
      type: String,
      enum: ["pending", "in-progress", "resolved", "closed"],
      default: "pending",
    },
    
    // Priority level
    priority: {
      type: String,
      enum: ["low", "medium", "high", "urgent"],
      default: "medium",
    },
    
    // Admin notes/response
    adminNotes: {
      type: String,
      default: "",
    },
    
    adminResponse: {
      type: String,
      default: "",
    },
    
    // Who handled this inquiry
    handledBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Admin",
    },
    
    // Timestamps for tracking
    respondedAt: {
      type: Date,
    },
    
    resolvedAt: {
      type: Date,
    },
    
    // Is the inquiry read by admin
    isRead: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

// Indexes for faster queries
contactInquirySchema.index({ user: 1 });
contactInquirySchema.index({ status: 1 });
contactInquirySchema.index({ createdAt: -1 });
contactInquirySchema.index({ isRead: 1 });

const ContactInquiry = mongoose.model("ContactInquiry", contactInquirySchema);
export default ContactInquiry;
