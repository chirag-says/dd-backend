import mongoose from "mongoose";

const savedSearchSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    name: { type: String, required: true },
    filters: {
      search: { type: String, default: "" },
      city: { type: String, default: "" },
      propertyType: { type: String, default: "" },
      priceRange: { type: String, default: "" },
      availableFor: { type: String, default: "" },
    },
    notifyEmail: { type: Boolean, default: true },
    notifyInApp: { type: Boolean, default: true },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);

const SavedSearch = mongoose.model("SavedSearch", savedSearchSchema);
export default SavedSearch;
