import express from "express";
import { authMiddleware } from "../middleware/authUser.js";
import {
  getMyNotifications,
  markNotificationRead,
  markAllNotificationsRead,
} from "../controllers/notificationController.js";

const router = express.Router();

router.use(authMiddleware);

router.get("/", getMyNotifications);
router.patch("/:id/read", markNotificationRead);
router.patch("/mark-all/read", markAllNotificationsRead);

export default router;
