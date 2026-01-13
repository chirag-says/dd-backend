import express from "express";
import { authMiddleware } from "../middleware/authUser.js";
import { protectAdmin } from "../middleware/authAdmin.js";
import {
  createInquiry,
  getAllInquiries,
  getInquiryById,
  updateInquiry,
  deleteInquiry,
  markAsRead,
  markAllAsRead,
  getMyInquiries,
} from "../controllers/contactController.js";

const router = express.Router();

// User routes (requires user auth)
router.post("/", authMiddleware, createInquiry);
router.get("/my-inquiries", authMiddleware, getMyInquiries);

// Admin routes (requires admin auth)
router.get("/admin/all", protectAdmin, getAllInquiries);
router.get("/admin/:id", protectAdmin, getInquiryById);
router.put("/admin/:id", protectAdmin, updateInquiry);
router.delete("/admin/:id", protectAdmin, deleteInquiry);
router.patch("/admin/:id/read", protectAdmin, markAsRead);
router.patch("/admin/mark-all-read", protectAdmin, markAllAsRead);

export default router;
