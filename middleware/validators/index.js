/**
 * Express-Validator Schemas for Security Hardening
 * Implements strict whitelisting to prevent mass assignment attacks
 */
import { body, param, query, validationResult } from 'express-validator';

// ============================================
// VALIDATION RESULT HANDLER
// ============================================

/**
 * Middleware to handle validation errors
 * Returns sanitized error messages without exposing internals
 */
export const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // Return generic validation error without exposing field details to potential attackers
        const safeErrors = errors.array().map(err => ({
            field: err.path,
            message: err.msg
        }));

        return res.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: safeErrors
        });
    }
    next();
};

// ============================================
// SANITIZATION HELPERS
// ============================================

/**
 * Whitelist allowed fields for a request body
 * Removes any fields not in the allowed list to prevent mass assignment
 */
export const whitelistFields = (allowedFields) => {
    return (req, res, next) => {
        if (req.body && typeof req.body === 'object') {
            const sanitizedBody = {};
            for (const field of allowedFields) {
                if (Object.prototype.hasOwnProperty.call(req.body, field)) {
                    sanitizedBody[field] = req.body[field];
                }
            }
            req.body = sanitizedBody;
        }
        next();
    };
};

// ============================================
// PROPERTY VALIDATORS
// ============================================

// Fields allowed when creating a property
const PROPERTY_CREATE_FIELDS = [
    'title', 'description', 'price', 'deposit', 'listingType', 'propertyType',
    'propertyTypeName', 'category', 'categoryName', 'subcategory', 'bhk',
    'bedrooms', 'bathrooms', 'balconies', 'area', 'parking', 'address',
    'flooring', 'furnishing', 'facing', 'age', 'availableFrom', 'features',
    'legal', 'extras', 'amenities', 'negotiable', 'imageCategoryMap',
    'latitude', 'longitude', 'propertyCategory',
    // Additional fields sent by AddProperty form
    'city', 'locality', 'priceUnit', 'gstApplicable', 'videoUrl', 'ageOfProperty',
    'bookingAmount', 'securityDeposit', 'maintenance', 'maintenanceIncluded'
];

// Fields allowed when updating own property (excludes sensitive fields)
const PROPERTY_UPDATE_FIELDS = [
    ...PROPERTY_CREATE_FIELDS,
    'existingCategorizedImages', 'imagesToRemove'
];

// DANGEROUS fields that should NEVER be allowed from client
const PROPERTY_FORBIDDEN_FIELDS = [
    'owner', 'isApproved', 'rejectionReason', 'views', 'likes',
    'interestedUsers', '_id', 'createdAt', 'updatedAt', '__v'
];

export const validatePropertyCreate = [
    whitelistFields(PROPERTY_CREATE_FIELDS),

    body('title')
        .optional()
        .trim()
        .isLength({ min: 3, max: 300 })
        .withMessage('Title must be between 3 and 300 characters'),

    body('description')
        .optional()
        .trim()
        .isLength({ max: 5000 })
        .withMessage('Description cannot exceed 5000 characters'),

    body('price')
        .optional()
        .isNumeric()
        .withMessage('Price must be a number')
        .toFloat(),

    body('listingType')
        .optional()
        .isIn(['sale', 'rent', 'lease', 'Sale', 'Rent', 'Lease'])
        .withMessage('Invalid listing type'),

    body('bhk')
        .optional()
        .isString()
        .withMessage('BHK must be a string'),

    body('bedrooms')
        .optional()
        .isInt({ min: 0, max: 50 })
        .withMessage('Bedrooms must be between 0 and 50'),

    body('bathrooms')
        .optional()
        .isInt({ min: 0, max: 50 })
        .withMessage('Bathrooms must be between 0 and 50'),

    handleValidationErrors
];

export const validatePropertyUpdate = [
    whitelistFields(PROPERTY_UPDATE_FIELDS),

    param('id')
        .isMongoId()
        .withMessage('Invalid property ID'),

    body('title')
        .optional()
        .trim()
        .isLength({ min: 5, max: 200 })
        .withMessage('Title must be between 5 and 200 characters')
        .escape(),

    body('description')
        .optional()
        .trim()
        .isLength({ max: 5000 })
        .withMessage('Description cannot exceed 5000 characters'),

    body('price')
        .optional()
        .isNumeric()
        .withMessage('Price must be a number')
        .toFloat(),

    handleValidationErrors
];

// ============================================
// LEAD VALIDATORS
// ============================================

const LEAD_UPDATE_FIELDS = ['status', 'notes'];

export const validateLeadStatusUpdate = [
    whitelistFields(LEAD_UPDATE_FIELDS),

    param('id')
        .isMongoId()
        .withMessage('Invalid lead ID'),

    body('status')
        .optional()
        .isIn(['new', 'contacted', 'interested', 'negotiating', 'converted', 'lost'])
        .withMessage('Invalid lead status'),

    body('notes')
        .optional()
        .trim()
        .isLength({ max: 2000 })
        .withMessage('Notes cannot exceed 2000 characters'),

    handleValidationErrors
];

export const validateContactHistory = [
    param('id')
        .isMongoId()
        .withMessage('Invalid lead ID'),

    body('action')
        .trim()
        .notEmpty()
        .withMessage('Action is required')
        .isLength({ max: 100 })
        .withMessage('Action cannot exceed 100 characters'),

    body('note')
        .optional()
        .trim()
        .isLength({ max: 1000 })
        .withMessage('Note cannot exceed 1000 characters'),

    handleValidationErrors
];

// ============================================
// SAVED SEARCH VALIDATORS
// ============================================

const SAVED_SEARCH_FIELDS = ['name', 'filters', 'notifyEmail', 'notifyInApp'];

export const validateSavedSearchCreate = [
    whitelistFields(SAVED_SEARCH_FIELDS),

    body('name')
        .trim()
        .notEmpty()
        .withMessage('Search name is required')
        .isLength({ max: 100 })
        .withMessage('Name cannot exceed 100 characters')
        .escape(),

    body('filters')
        .isObject()
        .withMessage('Filters must be an object'),

    body('filters.search')
        .optional()
        .trim()
        .isLength({ max: 200 })
        .withMessage('Search term cannot exceed 200 characters'),

    body('filters.city')
        .optional()
        .trim()
        .isLength({ max: 100 })
        .withMessage('City cannot exceed 100 characters'),

    body('filters.propertyType')
        .optional()
        .trim()
        .isLength({ max: 50 })
        .withMessage('Property type cannot exceed 50 characters'),

    body('filters.priceRange')
        .optional()
        .isIn(['', 'low', 'mid', 'high'])
        .withMessage('Invalid price range'),

    body('filters.availableFor')
        .optional()
        .isIn(['', 'sale', 'rent', 'lease', 'Sale', 'Rent', 'Lease'])
        .withMessage('Invalid availability type'),

    body('notifyEmail')
        .optional()
        .isBoolean()
        .toBoolean(),

    body('notifyInApp')
        .optional()
        .isBoolean()
        .toBoolean(),

    handleValidationErrors
];

// ============================================
// USER PROFILE VALIDATORS
// ============================================

const PROFILE_UPDATE_FIELDS = [
    'name', 'phone', 'alternatePhone', 'address', 'dateOfBirth',
    'gender', 'bio', 'preferences'
];

// DANGEROUS fields users should NEVER be able to set
const USER_FORBIDDEN_FIELDS = [
    'role', 'isVerified', 'isBlocked', 'isActive', 'email', 'password',
    'otp', 'otpExpires', 'security', '_id', 'createdAt', 'updatedAt'
];

export const validateProfileUpdate = [
    whitelistFields(PROFILE_UPDATE_FIELDS),

    body('name')
        .optional()
        .trim()
        .isLength({ min: 2, max: 100 })
        .withMessage('Name must be between 2 and 100 characters'),

    body('phone')
        .optional()
        .matches(/^[6-9]\d{9}$/)
        .withMessage('Please provide a valid 10-digit Indian phone number'),

    body('alternatePhone')
        .optional()
        .matches(/^[6-9]\d{9}$/)
        .withMessage('Please provide a valid 10-digit phone number'),

    body('bio')
        .optional()
        .trim()
        .isLength({ max: 500 })
        .withMessage('Bio cannot exceed 500 characters'),

    body('gender')
        .optional()
        .isIn(['Male', 'Female', 'Other', ''])
        .withMessage('Invalid gender'),

    handleValidationErrors
];

// ============================================
// REPORT VALIDATORS
// ============================================

export const validatePropertyReport = [
    param('id')
        .isMongoId()
        .withMessage('Invalid property ID'),

    body('reason')
        .trim()
        .notEmpty()
        .withMessage('Report reason is required')
        .isLength({ min: 10, max: 1000 })
        .withMessage('Reason must be between 10 and 1000 characters'),

    handleValidationErrors
];

// ============================================
// COMMON VALIDATORS
// ============================================

export const validateMongoId = (paramName = 'id') => [
    param(paramName)
        .isMongoId()
        .withMessage(`Invalid ${paramName}`),
    handleValidationErrors
];

export const validatePagination = [
    query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer')
        .toInt(),

    query('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be between 1 and 100')
        .toInt(),

    handleValidationErrors
];

// Export forbidden fields for reference
export { PROPERTY_FORBIDDEN_FIELDS, USER_FORBIDDEN_FIELDS };
