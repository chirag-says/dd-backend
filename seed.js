import mongoose from "mongoose";
import PropertyType from "./models/PropertyType.js";
import Category from "./models/Category.js";
import SubCategory from "./models/SubCategory.js";

// HOSTINGER CLOUD FIX: Only load dotenv in non-production
if (process.env.NODE_ENV !== "production") {
    const dotenv = await import("dotenv");
    dotenv.default.config();
}

const PROPERTY_CATEGORIES = {
    Residential: {
        types: ["Apartment", "Independent House", "Villa", "Studio Apartment", "Penthouse"],
        subtypes: ["1 RK", "1 BHK", "2 BHK", "3 BHK", "4 BHK", "5+ BHK"]
    },
    Commercial: {
        types: ["Office Space", "Shop / Showroom", "Warehouse/Godown", "Co-working", "Industrial Shed"],
        subtypes: ["Standard"]
    },
    Plot: {
        types: ["Residential Plot", "Commercial Property", "Industrial Land", "Agricultural Land"],
        subtypes: ["Standard"]
    }
};

const seed = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log("Connected to MongoDB");

        // Clear existing data (optional, but good for syncing)
        // await PropertyType.deleteMany({});
        // await Category.deleteMany({});
        // await SubCategory.deleteMany({});

        for (const [pTypeName, data] of Object.entries(PROPERTY_CATEGORIES)) {
            // 1. Create/Find PropertyType
            let pType = await PropertyType.findOne({ name: pTypeName });
            if (!pType) {
                pType = await PropertyType.create({ name: pTypeName });
                console.log(`Created PropertyType: ${pTypeName}`);
            }

            for (const catName of data.types) {
                // 2. Create/Find Category
                let cat = await Category.findOne({ name: catName, propertyType: pType._id });
                if (!cat) {
                    cat = await Category.create({ name: catName, propertyType: pType._id });
                    console.log(`  Created Category: ${catName}`);
                }

                // 3. Create/Find SubCategories
                for (const subName of data.subtypes) {
                    let sub = await SubCategory.findOne({ name: subName, category: cat._id });
                    if (!sub) {
                        sub = await SubCategory.create({
                            name: subName,
                            category: cat._id,
                            propertyType: pType._id
                        });
                        console.log(`    Created SubCategory: ${subName}`);
                    }
                }
            }
        }

        console.log("Seeding completed successfully.");
        process.exit(0);
    } catch (error) {
        console.error("Seeding failed:", error);
        process.exit(1);
    }
};

seed();