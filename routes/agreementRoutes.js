/**
 * Agreement Routes - Secure Financial/Legal Workflow Endpoints
 * 
 * ACCESS CONTROL:
 * - User routes: Owners and Buyers only (NO Agents)
 * - Admin routes: Admin authentication required
 * - Public routes: Templates and states list
 */

import express from "express";
import { authMiddleware, requireRole } from "../middleware/authUser.js";
import { protectAdmin } from "../middleware/authAdmin.js";
import { requireUserRole, blockRetiredRoles } from "../middleware/roleGuard.js";
import { validateMongoId } from "../middleware/validators/index.js";
import {
  generateAgreement,
  getMyAgreements,
  getAgreementById,
  signAgreement,
  validatePaymentWebhook,
  getAgreementTemplates,
  getIndianStates,
  getAllAgreementsAdmin,
} from "../controllers/agreementController.js";

const router = express.Router();

// ============================================
// PUBLIC ROUTES (No authentication required)
// ============================================

// Get available templates (public info)
router.get("/templates", getAgreementTemplates);

// Get Indian states list (public)
router.get("/states", getIndianStates);

// ============================================
// PROTECTED ROUTES - Owners and Buyers ONLY
// Block any retired roles (including Agent)
// ============================================

// Apply auth and role blocking to all protected routes
router.use(authMiddleware);
router.use(blockRetiredRoles); // Global block for retired roles

// Generate agreement (Owners and Buyers only)
router.post(
  "/generate",
  requireUserRole('owner', 'user'),
  generateAgreement
);

// Get user's agreements (only returns their own)
router.get(
  "/my-agreements",
  requireUserRole('owner', 'user'),
  getMyAgreements
);

// Get single agreement by ID (IDOR protected in controller)
router.get(
  "/:id",
  requireUserRole('owner', 'user'),
  validateMongoId('id'),
  getAgreementById
);

// Sign agreement (only parties can sign)
router.post(
  "/:id/sign",
  requireUserRole('owner', 'user'),
  validateMongoId('id'),
  signAgreement
);

// ============================================
// PAYMENT WEBHOOK ROUTE
// Special authentication - uses webhook signature
// ============================================

// Webhook for payment validation (separate validation in controller)
router.post(
  "/webhook/payment",
  express.json({ type: 'application/json' }), // Raw body for signature verification
  validatePaymentWebhook
);

// ============================================
// ADMIN ROUTES
// ============================================

// Get all agreements (admin only)
router.get(
  "/admin/all",
  protectAdmin,
  getAllAgreementsAdmin
);

export default router;
