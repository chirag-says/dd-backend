// models/SubCategory.js
import mongoose from "mongoose";

const subCategorySchema = new mongoose.Schema(
  {
    name: { type: String, required: true },

    category: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Category",
      required: true,
    },

    propertyType: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "PropertyType",
      required: true,
    },
  },
  { timestamps: true }
);

export default mongoose.model("SubCategory", subCategorySchema);
