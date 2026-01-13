import express from "express";
import { authMiddleware } from "../middleware/authUser.js";
import {
  getOwnerLeads,
  getPropertyLeads,
  updateLeadStatus,
  markLeadViewed,
  addContactHistory,
  getLeadAnalytics,
  exportLeadsToExcel
} from "../controllers/leadController.js";
import {
  validateLeadStatusUpdate,
  validateContactHistory,
  validateMongoId,
  validatePagination,
} from "../middleware/validators/index.js";

const router = express.Router();

// All routes require authentication
router.use(authMiddleware);

// Get all leads for the logged-in property owner (with pagination validation)
router.get("/", validatePagination, getOwnerLeads);

// Get lead analytics for dashboard
router.get("/analytics", getLeadAnalytics);

// Export leads to Excel
router.get("/export", exportLeadsToExcel);

// Get leads for a specific property
router.get("/property/:propertyId", validateMongoId('propertyId'), getPropertyLeads);

// Update lead status (with validation)
router.put("/:id/status", validateLeadStatusUpdate, updateLeadStatus);

// Mark lead as viewed
router.put("/:id/viewed", validateMongoId('id'), markLeadViewed);

// Add contact history entry (with validation)
router.post("/:id/contact", validateContactHistory, addContactHistory);

export default router;

