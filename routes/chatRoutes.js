import express from "express";
import jwt from "jsonwebtoken";
import {
  startConversation,
  getConversations,
  getMessages,
  sendMessage,
  getUnreadCount,
  deleteConversation,
} from "../controllers/chatController.js";
import { authMiddleware } from "../middleware/authUser.js";

const router = express.Router();

// All chat routes require authentication
router.use(authMiddleware);

// ============================================
// SECURITY FIX: Socket Authentication Token
// Provides a short-lived JWT for Socket.io authentication
// This prevents identity spoofing in real-time connections
// ============================================
router.get("/socket-token", (req, res) => {
  try {
    // Generate a short-lived token specifically for socket authentication
    const socketToken = jwt.sign(
      {
        id: req.user._id.toString(),
        purpose: 'socket_auth',
        iat: Math.floor(Date.now() / 1000)
      },
      process.env.JWT_SECRET,
      { expiresIn: '5m' } // Only valid for 5 minutes
    );

    res.status(200).json({
      success: true,
      token: socketToken,
    });
  } catch (error) {
    console.error("Error generating socket token:", error);
    res.status(500).json({
      success: false,
      message: "Failed to generate socket authentication token",
    });
  }
});

// Start or get existing conversation
router.post("/conversation/start", startConversation);

// Get all conversations for logged-in user
router.get("/conversations", getConversations);

// Get messages for a conversation
router.get("/messages/:conversationId", getMessages);

// Send a message
router.post("/message/send", sendMessage);

// Get unread message count
router.get("/unread-count", getUnreadCount);

// Delete/Archive a conversation
router.delete("/conversation/:conversationId", deleteConversation);

export default router;
