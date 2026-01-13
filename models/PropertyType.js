import mongoose from "mongoose";

const propertyTypeSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true },
  },
  { timestamps: true }
);

export default mongoose.model("PropertyType", propertyTypeSchema);
