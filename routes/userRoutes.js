/**
 * User Routes
 * Enterprise-grade authentication with secure endpoints
 */
import express from "express";
import multer from "multer";
import {
  registerUser,
  registerUserDirect,
  verifyOtp,
  resendOtp,
  loginUser,
  logoutUser,
  logoutAllDevices,
  getProfile,
  updateProfile,
  changePassword,
  sendUpgradeOtp,
  verifyUpgradeOtp,
  forgotPassword,
  resetPassword,
  validateResetToken,
  getActiveSessions,
  revokeSession,
  getAllUsers,
  toggleBlockUser,
  exportUsersPDF,
  exportUsersCSV,
  exportOwnersPDF,
  exportOwnersCSV
} from "../controllers/userController.js";
import { addProperty, getOwnersWithProjects } from "../controllers/propertyController.js";
import {
  authMiddleware,
  optionalAuth,
  requireRole,
  requireVerified,
  authRateLimit
} from "../middleware/authUser.js";
import { upload, uploadConcurrencyGuard } from "../middleware/upload.js";
import { protectAdmin } from "../middleware/authAdmin.js";
import { validateProfileUpdate } from "../middleware/validators/index.js";

const router = express.Router();

// Local storage for fallback
const localStorage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});
const localUpload = multer({ storage: localStorage });

// ============================================
// PUBLIC AUTH ROUTES (Rate limited)
// ============================================

// Registration
router.post("/register", authRateLimit, registerUser);
router.post("/register-direct", authRateLimit, registerUserDirect);
router.post("/verify-otp", authRateLimit, verifyOtp);
router.post("/resend-otp", authRateLimit, resendOtp);

// Login
router.post("/login", authRateLimit, loginUser);

// Password Reset (public)
router.post("/forgot-password", authRateLimit, forgotPassword);
router.get("/reset-password/validate/:token", validateResetToken);
router.post("/reset-password", authRateLimit, resetPassword);

// ============================================
// PROTECTED AUTH ROUTES
// ============================================

// Logout
router.post("/logout", authMiddleware, logoutUser);
router.post("/logout-all", authMiddleware, logoutAllDevices);

// Session Management
router.get("/sessions", authMiddleware, getActiveSessions);
router.delete("/sessions/:sessionId", authMiddleware, revokeSession);

// ============================================
// PROFILE ROUTES (Protected with validation)
// ============================================

router.get("/profile", authMiddleware, getProfile);
router.get("/me", authMiddleware, getProfile); // Alias for /profile - standard REST pattern
router.put("/profile", authMiddleware, validateProfileUpdate, uploadConcurrencyGuard, upload.single("profileImage"), updateProfile);
router.put("/change-password", authMiddleware, changePassword);

// ============================================
// UPGRADE ROUTES (Buyer to Owner)
// ============================================

router.post("/send-upgrade-otp", authMiddleware, requireVerified, sendUpgradeOtp);
router.post("/verify-upgrade-otp", authMiddleware, requireVerified, verifyUpgradeOtp);

// ============================================
// PROPERTY ROUTES (Owner only)
// ============================================

router.post(
  "/add-property",
  authMiddleware,
  requireVerified,
  requireRole("owner"),
  uploadConcurrencyGuard,
  localUpload.array("images", 10),
  addProperty
);

// ============================================
// ADMIN ROUTES (Admin protected)
// ============================================

router.get("/list", protectAdmin, getAllUsers);
router.put("/block/:id", protectAdmin, toggleBlockUser);
router.get("/owners-projects", protectAdmin, getOwnersWithProjects);
router.get("/export-csv", protectAdmin, exportUsersCSV);
router.get("/export-pdf", protectAdmin, exportUsersPDF);
router.get("/export-owners-csv", protectAdmin, exportOwnersCSV);
router.get("/export-owners-pdf", protectAdmin, exportOwnersPDF);

export default router;
