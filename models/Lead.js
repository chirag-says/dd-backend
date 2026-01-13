import mongoose from "mongoose";

const leadSchema = new mongoose.Schema(
  {
    // Property reference
    property: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: "Property", 
      required: true 
    },
    
    // Property owner (for easy querying)
    propertyOwner: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: "User", 
      required: true 
    },
    
    // Interested user details
    user: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: "User", 
      required: true 
    },
    
    // Snapshot of user data at time of interest (in case user updates profile later)
    userSnapshot: {
      name: { type: String, required: true },
      email: { type: String, required: true },
      phone: { type: String },
      profileImage: { type: String }
    },
    
    // Property snapshot for quick display
    propertySnapshot: {
      title: { type: String },
      price: { type: Number },
      listingType: { type: String },
      city: { type: String },
      locality: { type: String },
      propertyType: { type: String },
      bhk: { type: String }
    },
    
    // Lead status
    status: { 
      type: String, 
      enum: ["new", "contacted", "interested", "negotiating", "converted", "lost"],
      default: "new"
    },
    
    // Owner notes about this lead
    notes: { type: String },
    
    // Contact history
    contactHistory: [{
      action: { type: String }, // 'called', 'emailed', 'whatsapp', 'met'
      note: { type: String },
      date: { type: Date, default: Date.now }
    }],
    
    // Track if owner has viewed this lead
    isViewed: { type: Boolean, default: false },
    viewedAt: { type: Date },
    
    // Source of lead
    source: { 
      type: String, 
      enum: ["website", "mobile_app", "direct"],
      default: "website"
    }
  },
  { timestamps: true }
);

// Indexes for faster querying
leadSchema.index({ propertyOwner: 1, createdAt: -1 });
leadSchema.index({ property: 1 });
leadSchema.index({ status: 1 });
leadSchema.index({ user: 1, property: 1 }, { unique: true }); // Prevent duplicate leads

const Lead = mongoose.model("Lead", leadSchema);
export default Lead;
