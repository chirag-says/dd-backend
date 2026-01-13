/**
 * Simple Diagnostic Script
 */
import mongoose from "mongoose";

// HOSTINGER CLOUD FIX: Only load dotenv in non-production
if (process.env.NODE_ENV !== "production") {
    const dotenv = await import("dotenv");
    dotenv.default.config();
}

async function run() {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log("Connected");

        // Check Admin collection directly
        const db = mongoose.connection.db;
        const admins = await db.collection("admins").find({}).limit(2).toArray();

        console.log("Total admins found:", admins.length);

        for (const admin of admins) {
            console.log("---");
            console.log("Email:", admin.email);
            console.log("Has password:", !!admin.password);
            console.log("Role type:", typeof admin.role);
            console.log("Role value:", admin.role);
            console.log("isActive:", admin.isActive);
            console.log("mfa:", JSON.stringify(admin.mfa));
            console.log("security:", JSON.stringify(admin.security));
        }

    } catch (err) {
        console.error("Error:", err.message);
    } finally {
        await mongoose.disconnect();
    }
}

run();
