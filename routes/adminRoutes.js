import express from "express";
import {
  // registerAdmin - REMOVED: Admins are now created via database seeding only (security hardening)
  loginAdmin,
  logoutAdmin,
  logoutAllSessions,
  verifyMfa,
  setupMfa,
  confirmMfaSetup,
  disableMfa,
  getAdminProfile,
  getActiveSessions,
  revokeSession,
  changePassword,
  getDashboardStats,
  getAdminLeads,
  updateAdminLeadStatus,
  getAdminReports,
  updateReportStatus,
  getAuditLogs,
} from "../controllers/adminController.js";
import {
  protectAdmin,
  requirePermission,
  // requireRoleLevel - REMOVED: No longer needed (admin registration removed)
  requireSuperAdmin,
  authRateLimit,
} from "../middleware/authAdmin.js";
import { getAllLeads } from "../controllers/leadController.js";

const router = express.Router();

// ============================================
// PUBLIC ROUTES (No authentication required)
// ============================================

// Authentication
router.post("/login", authRateLimit, loginAdmin);

// MFA verification (after login, before full session)
router.post("/mfa/verify", authRateLimit, verifyMfa);

// ============================================
// PROTECTED ROUTES (Authentication required)
// ============================================

// Session management
router.post("/logout", protectAdmin, logoutAdmin);
router.post("/logout-all", protectAdmin, logoutAllSessions);
router.get("/sessions", protectAdmin, getActiveSessions);
router.delete("/sessions/:sessionId", protectAdmin, revokeSession);

// Profile & Security
router.get("/profile", protectAdmin, getAdminProfile);
router.post("/change-password", protectAdmin, changePassword);

// MFA management
router.post("/mfa/setup", protectAdmin, setupMfa);
router.post("/mfa/confirm", protectAdmin, confirmMfaSetup);
router.post("/mfa/disable", protectAdmin, disableMfa);

// Dashboard & Analytics
router.get("/dashboard/stats", protectAdmin, requirePermission("dashboard:read"), getDashboardStats);

// Leads Management
router.get("/leads", protectAdmin, requirePermission("leads:read"), getAllLeads);
router.put("/leads/:id", protectAdmin, requirePermission("leads:update"), updateAdminLeadStatus);

// Reports Management
router.get("/reports", protectAdmin, requirePermission("reports:read"), getAdminReports);
router.put("/reports/:id", protectAdmin, requirePermission("reports:update"), updateReportStatus);

// ============================================
// ADMIN MANAGEMENT ROUTES (High privilege)
// ============================================

// SECURITY: Admin registration endpoint REMOVED
// Admins are now created via database seeding only
// Run: node seedAdmin.js (from backend directory)
// This eliminates the registration attack surface entirely

// Audit Logs (Super Admin only)
router.get("/audit-logs", protectAdmin, requireSuperAdmin, getAuditLogs);

export default router;
