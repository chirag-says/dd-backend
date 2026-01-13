/**
 * Legacy User Migration Script
 * 
 * Purpose: Migrate all legacy users to be compatible with the new RBAC
 * and HttpOnly cookie authentication system.
 * 
 * Run with: node scripts/migrateLegacyUsers.js
 */

import mongoose from 'mongoose';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// HOSTINGER CLOUD FIX: Only load dotenv in non-production
if (process.env.NODE_ENV !== "production") {
    const dotenv = await import('dotenv');
    dotenv.default.config({ path: path.join(__dirname, '..', '.env') });
}

// Import User model
import User from '../models/userModel.js';

// ============================================
// MIGRATION CONFIGURATION
// ============================================

const DEFAULT_ROLE = 'buyer'; // Default role for legacy users without a role
const VALID_ROLES = ['user', 'buyer', 'owner']; // 'user' and 'buyer' are equivalent, both accepted
const RETIRED_ROLES = ['agent', 'Agent', 'AGENT'];

// ============================================
// MIGRATION FUNCTIONS
// ============================================

const migrateUser = async (user) => {
    const updates = {};
    const logs = [];

    // 1. Migrate role
    if (!user.role || RETIRED_ROLES.includes(user.role)) {
        updates.role = DEFAULT_ROLE;
        logs.push(`Role: ${user.role || 'undefined'} -> ${DEFAULT_ROLE}`);
    } else if (!VALID_ROLES.includes(user.role)) {
        updates.role = DEFAULT_ROLE;
        logs.push(`Invalid role '${user.role}' -> ${DEFAULT_ROLE}`);
    }

    // 2. Initialize security metadata if missing
    if (!user.security) {
        updates.security = {
            failedLoginAttempts: 0,
            lockoutUntil: null,
            passwordChangedAt: null,
            lastLoginAt: null,
            lastLoginIp: null,
            sessionVersion: 0,
        };
        logs.push('Security metadata: initialized');
    } else {
        // Initialize individual security fields if missing
        if (user.security.failedLoginAttempts === undefined) {
            updates['security.failedLoginAttempts'] = 0;
            logs.push('security.failedLoginAttempts: initialized to 0');
        }
        if (user.security.sessionVersion === undefined) {
            updates['security.sessionVersion'] = 0;
            logs.push('security.sessionVersion: initialized to 0');
        }
        if (user.security.lockoutUntil === undefined) {
            updates['security.lockoutUntil'] = null;
            logs.push('security.lockoutUntil: initialized to null');
        }
    }

    // 3. Initialize preferences if missing
    if (!user.preferences) {
        updates.preferences = {
            emailNotifications: true,
            smsNotifications: false,
        };
        logs.push('Preferences: initialized with defaults');
    }

    // 4. Ensure isActive and isBlocked have values
    if (user.isActive === undefined) {
        updates.isActive = true;
        logs.push('isActive: set to true');
    }
    if (user.isBlocked === undefined) {
        updates.isBlocked = false;
        logs.push('isBlocked: set to false');
    }

    // 5. Ensure isVerified has a value
    if (user.isVerified === undefined) {
        // If user has logged in before (has sessions or has been active), mark as verified
        updates.isVerified = true; // Legacy users are considered verified
        logs.push('isVerified: set to true (legacy user)');
    }

    // Apply updates if any
    if (Object.keys(updates).length > 0) {
        await User.findByIdAndUpdate(user._id, { $set: updates });
        return { updated: true, logs };
    }

    return { updated: false, logs: ['No updates needed'] };
};

const runMigration = async () => {
    console.log('═'.repeat(60));
    console.log('🔄 LEGACY USER MIGRATION SCRIPT');
    console.log('═'.repeat(60));
    console.log(`Started at: ${new Date().toISOString()}`);
    console.log();

    try {
        // Connect to MongoDB
        console.log('📡 Connecting to MongoDB...');
        await mongoose.connect(process.env.MONGO_URI);
        console.log('✅ Connected to MongoDB\n');

        // Get all users
        const users = await User.find({}).select('+security');
        console.log(`📊 Found ${users.length} users to check\n`);

        let updatedCount = 0;
        let skippedCount = 0;
        let errorCount = 0;

        // Process each user
        for (let i = 0; i < users.length; i++) {
            const user = users[i];
            console.log(`[${i + 1}/${users.length}] Processing: ${user.email}`);

            try {
                const result = await migrateUser(user);

                if (result.updated) {
                    updatedCount++;
                    console.log(`   ✅ Updated:`);
                    result.logs.forEach(log => console.log(`      - ${log}`));
                } else {
                    skippedCount++;
                    console.log(`   ⏭️  Skipped (already migrated)`);
                }
            } catch (error) {
                errorCount++;
                console.log(`   ❌ Error: ${error.message}`);
            }
        }

        // Print summary
        console.log('\n' + '═'.repeat(60));
        console.log('📊 MIGRATION SUMMARY');
        console.log('═'.repeat(60));
        console.log(`Total users:     ${users.length}`);
        console.log(`Updated:         ${updatedCount}`);
        console.log(`Skipped:         ${skippedCount}`);
        console.log(`Errors:          ${errorCount}`);
        console.log(`Completed at:    ${new Date().toISOString()}`);
        console.log('═'.repeat(60));

        // Exit
        process.exit(0);
    } catch (error) {
        console.error('\n❌ Migration failed:', error.message);
        console.error(error.stack);
        process.exit(1);
    }
};

// Run the migration
runMigration();
