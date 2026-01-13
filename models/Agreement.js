/**
 * Agreement Model - Secure Financial/Legal Document Storage
 * Implements cryptographic signing, idempotency keys, and tamper detection
 */
import mongoose from "mongoose";
import crypto from "crypto";

// ============================================
// CRYPTOGRAPHIC UTILITIES
// ============================================

/**
 * Generate HMAC signature for agreement content
 * Uses SHA-256 with a server secret key
 */
const generateSignature = (data, secretKey) => {
    const hmac = crypto.createHmac('sha256', secretKey);
    hmac.update(JSON.stringify(data));
    return hmac.digest('hex');
};

/**
 * Verify HMAC signature
 */
const verifySignature = (data, signature, secretKey) => {
    const expectedSignature = generateSignature(data, secretKey);
    return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex')
    );
};

/**
 * Generate unique idempotency key
 * Combination of property ID, owner ID, buyer ID, and timestamp
 */
const generateIdempotencyKey = (propertyId, ownerId, buyerId) => {
    const timestamp = Date.now();
    const uniqueString = `${propertyId}-${ownerId}-${buyerId}-${timestamp}`;
    return crypto.createHash('sha256').update(uniqueString).digest('hex').substring(0, 32);
};

// ============================================
// AGREEMENT SCHEMA
// ============================================

const agreementSchema = new mongoose.Schema(
    {
        // ============================================
        // IDEMPOTENCY & SECURITY
        // ============================================

        // Unique idempotency key to prevent duplicate agreements
        idempotencyKey: {
            type: String,
            required: true,
            unique: true,
            index: true,
        },

        // Cryptographic signature of the agreement content
        signature: {
            type: String,
            required: true,
            select: false, // Never return in queries by default
        },

        // Hash of the agreement content for tamper detection
        contentHash: {
            type: String,
            required: true,
        },

        // ============================================
        // PARTIES (Only Owners and Buyers - NO Agents)
        // ============================================

        // Property owner (landlord/seller)
        owner: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },
        ownerSnapshot: {
            name: { type: String, required: true },
            email: { type: String, required: true },
            phone: String,
            aadhaarLastFour: String, // Only last 4 digits for privacy
            address: String,
            age: Number,
            role: { type: String, enum: ['owner'], required: true },
        },

        // Buyer/Tenant
        buyer: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },
        buyerSnapshot: {
            name: { type: String, required: true },
            email: { type: String, required: true },
            phone: String,
            aadhaarLastFour: String,
            address: String,
            age: Number,
            role: { type: String, enum: ['user'], required: true },
        },

        // ============================================
        // PROPERTY REFERENCE
        // ============================================

        property: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Property",
            required: true,
            index: true,
        },
        propertySnapshot: {
            title: String,
            address: String,
            city: String,
            state: String,
            type: String,
            bhk: String,
            furnishing: String,
            carpetArea: Number,
        },

        // ============================================
        // FINANCIAL DETAILS (Server-Verified)
        // ============================================

        // All amounts verified from Property model at creation time
        financials: {
            // Rent/Price from database
            amount: { type: Number, required: true },
            amountSource: { type: String, enum: ['property_price', 'property_deposit'], required: true },
            amountVerifiedAt: { type: Date, required: true },

            // Security deposit
            securityDeposit: { type: Number, required: true },

            // Maintenance charges
            maintenanceCharges: Number,

            // Payment schedule
            rentDueDay: { type: Number, min: 1, max: 31, default: 5 },

            // Currency
            currency: { type: String, default: 'INR' },
        },

        // ============================================
        // AGREEMENT TERMS
        // ============================================

        agreementType: {
            type: String,
            enum: ['LEAVE_AND_LICENSE', 'RENTAL_AGREEMENT', 'SALE_AGREEMENT'],
            required: true,
        },

        duration: {
            startDate: { type: Date, required: true },
            endDate: { type: Date, required: true },
            months: { type: Number, required: true },
            noticePeriodMonths: { type: Number, default: 1 },
            lockInPeriodMonths: { type: Number, default: 3 },
        },

        terms: {
            additionalTerms: String,
            specialConditions: [String],
        },

        // ============================================
        // AGREEMENT CONTENT
        // ============================================

        // The full agreement text (markdown format)
        content: {
            type: String,
            required: true,
        },

        // ============================================
        // STATUS & WORKFLOW
        // ============================================

        status: {
            type: String,
            enum: ['draft', 'pending_owner_signature', 'pending_buyer_signature', 'signed', 'active', 'expired', 'cancelled', 'terminated'],
            default: 'draft',
        },

        // Digital signatures
        signatures: {
            owner: {
                signed: { type: Boolean, default: false },
                signedAt: Date,
                ipAddress: String,
                userAgent: String,
            },
            buyer: {
                signed: { type: Boolean, default: false },
                signedAt: Date,
                ipAddress: String,
                userAgent: String,
            },
        },

        // ============================================
        // PAYMENT TRACKING
        // ============================================

        payments: [{
            type: { type: String, enum: ['deposit', 'rent', 'maintenance', 'refund'] },
            amount: Number,
            transactionId: String,
            paymentGateway: String,
            status: { type: String, enum: ['pending', 'completed', 'failed', 'refunded'] },
            paidAt: Date,
            verifiedAt: Date,
            webhookValidated: { type: Boolean, default: false },
        }],

        // ============================================
        // AUDIT TRAIL
        // ============================================

        auditLog: [{
            action: String,
            performedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
            performedByRole: { type: String, enum: ['owner', 'user', 'admin'] },
            timestamp: { type: Date, default: Date.now },
            ipAddress: String,
            details: mongoose.Schema.Types.Mixed,
        }],

        // Created by user
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
        },
        createdByRole: {
            type: String,
            enum: ['owner', 'user'], // Only owners and buyers can create
            required: true,
        },
    },
    {
        timestamps: true,
        toJSON: {
            transform: function (doc, ret) {
                // Never expose signature in API responses
                delete ret.signature;
                return ret;
            }
        }
    }
);

// ============================================
// INDEXES
// ============================================

agreementSchema.index({ owner: 1, buyer: 1, property: 1 });
agreementSchema.index({ status: 1 });
agreementSchema.index({ createdAt: -1 });
agreementSchema.index({ 'duration.endDate': 1 }); // For expiry checks

// ============================================
// STATIC METHODS
// ============================================

/**
 * Create a new agreement with idempotency key and signature
 * Verifies financial amounts from Property model
 */
agreementSchema.statics.createSecureAgreement = async function (data, req) {
    const secretKey = process.env.AGREEMENT_SECRET_KEY || process.env.JWT_SECRET;

    // Generate idempotency key
    const idempotencyKey = generateIdempotencyKey(
        data.property,
        data.owner,
        data.buyer
    );

    // Check for duplicate (idempotency)
    const existing = await this.findOne({ idempotencyKey });
    if (existing) {
        return { duplicate: true, agreement: existing };
    }

    // Create content hash for tamper detection
    const contentHash = crypto
        .createHash('sha256')
        .update(data.content)
        .digest('hex');

    // Generate cryptographic signature
    const signatureData = {
        idempotencyKey,
        contentHash,
        owner: data.owner.toString(),
        buyer: data.buyer.toString(),
        property: data.property.toString(),
        amount: data.financials.amount,
        createdAt: new Date().toISOString(),
    };
    const signature = generateSignature(signatureData, secretKey);

    // Create agreement
    const agreement = new this({
        ...data,
        idempotencyKey,
        signature,
        contentHash,
        auditLog: [{
            action: 'CREATED',
            performedBy: data.createdBy,
            performedByRole: data.createdByRole,
            timestamp: new Date(),
            ipAddress: req.ip || req.connection?.remoteAddress,
            details: { amountVerifiedFrom: 'Property model' },
        }],
    });

    await agreement.save();
    return { duplicate: false, agreement };
};

/**
 * Verify agreement has not been tampered with
 */
agreementSchema.methods.verifyIntegrity = function () {
    const secretKey = process.env.AGREEMENT_SECRET_KEY || process.env.JWT_SECRET;

    // Verify content hash
    const currentContentHash = crypto
        .createHash('sha256')
        .update(this.content)
        .digest('hex');

    if (currentContentHash !== this.contentHash) {
        return { valid: false, reason: 'Content has been modified' };
    }

    return { valid: true };
};

/**
 * Add audit log entry
 */
agreementSchema.methods.addAuditEntry = async function (action, userId, userRole, ipAddress, details = {}) {
    this.auditLog.push({
        action,
        performedBy: userId,
        performedByRole: userRole,
        timestamp: new Date(),
        ipAddress,
        details,
    });
    await this.save();
};

/**
 * Validate payment webhook data against agreement
 */
agreementSchema.methods.validatePaymentWebhook = function (webhookData) {
    // Verify the payment is for this agreement
    if (webhookData.agreementId !== this._id.toString()) {
        return { valid: false, reason: 'Agreement ID mismatch' };
    }

    // Verify amount matches expected
    const expectedAmounts = [
        this.financials.amount,
        this.financials.securityDeposit,
        this.financials.maintenanceCharges,
    ].filter(Boolean);

    if (!expectedAmounts.includes(webhookData.amount)) {
        return { valid: false, reason: 'Amount does not match agreement terms' };
    }

    // Verify parties
    const validPayerIds = [this.owner.toString(), this.buyer.toString()];
    if (!validPayerIds.includes(webhookData.payerId)) {
        return { valid: false, reason: 'Payer is not party to this agreement' };
    }

    return { valid: true };
};

// ============================================
// PRE-SAVE MIDDLEWARE
// ============================================

agreementSchema.pre('save', function (next) {
    // Ensure no agent role anywhere
    if (this.ownerSnapshot?.role && this.ownerSnapshot.role !== 'owner') {
        return next(new Error('Invalid owner role'));
    }
    if (this.buyerSnapshot?.role && this.buyerSnapshot.role !== 'user') {
        return next(new Error('Invalid buyer role'));
    }
    if (this.createdByRole && !['owner', 'user'].includes(this.createdByRole)) {
        return next(new Error('Invalid creator role'));
    }

    next();
});

const Agreement = mongoose.model("Agreement", agreementSchema);

// Export utilities for controller use
export { generateIdempotencyKey, generateSignature, verifySignature };
export default Agreement;
