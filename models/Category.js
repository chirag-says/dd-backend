import mongoose from "mongoose";

const categorySchema = new mongoose.Schema(
  {
    name: { type: String, required: true },

    propertyType: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "PropertyType",
      required: true,
    }
  },
  { timestamps: true }
);

export default mongoose.model("Category", categorySchema);
