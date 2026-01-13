import mongoose from "mongoose";

const connectDB = async () => {
  try {
    if (!process.env.MONGO_URI) {
      console.error("❌ MONGO_URI is not defined in environment variables");
      // process.exit(1); // Don't crash!
      return;
    }

    console.log("🔄 Connecting to MongoDB...");
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error("❌ MongoDB Connection Error:");
    console.error(`   Message: ${error.message}`);
    console.error(`   Code: ${error.code || 'N/A'}`);
    console.error(`   Name: ${error.name || 'N/A'}`);
    // process.exit(1); // Don't crash the server, just log error
    console.log("⚠️ Continuing server startup without database connection...");
  }
};

export default connectDB;
