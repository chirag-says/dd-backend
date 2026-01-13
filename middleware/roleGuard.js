/**
 * Role-Based Access Control (RBAC) Middleware
 * Enforces strict role checking - NO 'Agent' role allowed
 * 
 * Role Hierarchy:
 * - user (buyer): Can only access personal profile and saved properties
 * - owner: Can manage own properties and leads
 * - Admin/Manager roles are handled by authAdmin middleware
 */

// Valid roles in the system - Agent is PERMANENTLY RETIRED
// Both 'user' and 'buyer' are valid buyer roles (buyer is the new preferred term)
const VALID_USER_ROLES = ['user', 'buyer', 'owner'];

/**
 * Middleware to ensure the 'Agent' role is never used
 * This acts as a safety net across the entire application
 */
export const blockRetiredRoles = (req, res, next) => {
    // Check request body for attempts to set retired roles
    if (req.body?.role && !VALID_USER_ROLES.includes(req.body.role)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid role specified',
            code: 'INVALID_ROLE'
        });
    }

    // Check if authenticated user somehow has a retired role
    if (req.user?.role && !VALID_USER_ROLES.includes(req.user.role)) {
        console.error(`⚠️ SECURITY: User ${req.user._id} has retired role: ${req.user.role}`);
        return res.status(403).json({
            success: false,
            message: 'Your account role is invalid. Please contact support.',
            code: 'RETIRED_ROLE'
        });
    }

    next();
};

/**
 * Require specific roles for route access
 * Usage: requireUserRole('owner') or requireUserRole('user', 'owner')
 */
export const requireUserRole = (...allowedRoles) => {
    // Validate that no retired roles are being allowed
    for (const role of allowedRoles) {
        if (!VALID_USER_ROLES.includes(role)) {
            throw new Error(`Invalid role in requireUserRole: ${role}`);
        }
    }

    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required',
                code: 'NOT_AUTHENTICATED'
            });
        }

        // Block any retired roles
        if (!VALID_USER_ROLES.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: 'Invalid account role',
                code: 'INVALID_ROLE'
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: 'You do not have permission to access this resource',
                code: 'INSUFFICIENT_ROLE'
            });
        }

        next();
    };
};

/**
 * Restrict buyers to only their own resources
 * Buyers can only:
 * - View/update their own profile
 * - View/manage their saved properties (interest list)
 * - Create saved searches
 */
export const buyerAccessOnly = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required',
            code: 'NOT_AUTHENTICATED'
        });
    }

    // Buyers (role: 'user') have limited access
    if (req.user.role === 'user') {
        // Allow access - specific resource checks happen in controllers
        return next();
    }

    // Owners have broader access
    if (req.user.role === 'owner') {
        return next();
    }

    return res.status(403).json({
        success: false,
        message: 'Access denied',
        code: 'ACCESS_DENIED'
    });
};

/**
 * Ensure user can only modify listings if they are Owner role
 * Buyers cannot create, update, or delete property listings
 */
export const ownerOnlyListingAccess = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required',
            code: 'NOT_AUTHENTICATED'
        });
    }

    if (req.user.role !== 'owner') {
        return res.status(403).json({
            success: false,
            message: 'Only property owners can perform this action',
            code: 'OWNER_ONLY'
        });
    }

    next();
};

/**
 * Log role-related security events
 */
export const logRoleAccess = (action) => {
    return (req, res, next) => {
        if (req.user) {
            console.log(`[RBAC] ${action} - User: ${req.user._id}, Role: ${req.user.role}, Path: ${req.path}`);
        }
        next();
    };
};

/**
 * SECURITY FIX: Require ownership of a resource
 * 
 * Validates that the authenticated user owns the resource identified by
 * the request parameter. Uses constant-time comparison and validates
 * ObjectId format before querying.
 * 
 * @param {Function} getResourceByIdFn - Async function that takes resourceId and returns the resource document
 * @param {string} paramName - Name of the request param containing the resource ID (default: 'id')
 * @param {string} ownerField - Field name on the resource that contains the owner ID (default: 'owner')
 * 
 * Usage: requireOwnership(Property.findById.bind(Property), 'id', 'owner')
 */
export const requireOwnership = (getResourceByIdFn, paramName = 'id', ownerField = 'owner') => {
    // Validate ObjectId format pattern
    const objectIdPattern = /^[a-fA-F0-9]{24}$/;

    return async (req, res, next) => {
        try {
            // 1. Ensure user is authenticated
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required',
                    code: 'NOT_AUTHENTICATED'
                });
            }

            // 2. Get resource ID from params
            const resourceId = req.params[paramName];
            if (!resourceId) {
                console.warn(`[RBAC] Missing resource ID in param '${paramName}'`);
                return res.status(400).json({
                    success: false,
                    message: 'Resource identifier required',
                    code: 'MISSING_RESOURCE_ID'
                });
            }

            // 3. SECURITY: Validate ObjectId format before querying
            if (!objectIdPattern.test(resourceId)) {
                console.warn(`[RBAC] Invalid ObjectId format: ${resourceId}`);
                return res.status(400).json({
                    success: false,
                    message: 'Invalid resource identifier',
                    code: 'INVALID_RESOURCE_ID'
                });
            }

            // 4. Fetch the resource
            const resource = await getResourceByIdFn(resourceId);
            if (!resource) {
                return res.status(404).json({
                    success: false,
                    message: 'Resource not found',
                    code: 'NOT_FOUND'
                });
            }

            // 5. Get the owner ID from the resource
            const resourceOwnerId = resource[ownerField];
            if (!resourceOwnerId) {
                console.error(`[RBAC] Resource ${resourceId} has no owner field '${ownerField}'`);
                return res.status(500).json({
                    success: false,
                    message: 'Resource ownership cannot be determined',
                    code: 'OWNERSHIP_UNDEFINED'
                });
            }

            // 6. SECURITY: Constant-time comparison to prevent timing attacks
            const userIdStr = req.user._id.toString();
            const ownerIdStr = resourceOwnerId.toString();

            // Pad to same length for constant-time comparison
            const maxLen = Math.max(userIdStr.length, ownerIdStr.length);
            const paddedUserId = userIdStr.padEnd(maxLen, '\0');
            const paddedOwnerId = ownerIdStr.padEnd(maxLen, '\0');

            let isOwner = true;
            for (let i = 0; i < maxLen; i++) {
                if (paddedUserId.charCodeAt(i) !== paddedOwnerId.charCodeAt(i)) {
                    isOwner = false;
                }
            }

            if (!isOwner) {
                console.warn(`[RBAC] SECURITY: User ${userIdStr} attempted to access resource ${resourceId} owned by ${ownerIdStr}`);
                return res.status(403).json({
                    success: false,
                    message: 'You do not have permission to access this resource',
                    code: 'NOT_OWNER'
                });
            }

            // 7. Attach resource to request for use in controller
            req.resource = resource;

            next();
        } catch (err) {
            console.error('[RBAC] Ownership check error:', err);
            return res.status(500).json({
                success: false,
                message: 'Authorization check failed',
                code: 'OWNERSHIP_CHECK_ERROR'
            });
        }
    };
};

export { VALID_USER_ROLES };
