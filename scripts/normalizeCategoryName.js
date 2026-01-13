import mongoose from "mongoose";
import connectDB from "../config/db.js";
import Property from "../models/Property.js";

// HOSTINGER CLOUD FIX: Only load dotenv in non-production
if (process.env.NODE_ENV !== "production") {
  const dotenv = await import("dotenv");
  dotenv.default.config();
}

const inferCategoryName = (categoryName, propertyTypeName) => {
  const raw = (categoryName || "").toString();
  const lower = raw.toLowerCase();
  const typeRaw = (propertyTypeName || "").toString();
  const typeLower = typeRaw.toLowerCase();

  if (lower.includes("residen")) return "Residential";
  if (lower.includes("commercial")) return "Commercial";

  const isCommercialType = /office|shop|showroom|restaurant|cafe|warehouse|industrial|co-working|coworking|commercial/.test(
    typeLower
  );

  return isCommercialType ? "Commercial" : "Residential";
};

const run = async () => {
  try {
    await connectDB();

    const properties = await Property.find({});
    console.log(`Found ${properties.length} properties to inspect`);

    let updated = 0;

    for (const prop of properties) {
      const current = prop.categoryName;
      const normalized = inferCategoryName(current, prop.propertyTypeName || prop.propertyType);

      if (current !== normalized) {
        console.log(
          `Updating property ${prop._id}: categoryName "${current}" -> "${normalized}" (type: "${prop.propertyTypeName ||
          prop.propertyType}")`
        );
        prop.categoryName = normalized;
        await prop.save();
        updated += 1;
      }
    }

    console.log(`Done. Updated ${updated} properties.`);
  } catch (err) {
    console.error("Error normalizing category names", err);
  } finally {
    await mongoose.connection.close();
    process.exit(0);
  }
};

run();
