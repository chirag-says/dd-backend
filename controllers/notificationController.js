import Notification from "../models/Notification.js";

// Get current user's notifications
export const getMyNotifications = async (req, res) => {
  try {
    const userId = req.user?._id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const notifications = await Notification.find({ user: userId })
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    return res.json({ success: true, notifications });
  } catch (err) {
    console.error("getMyNotifications error:", err);
    return res.status(500).json({ success: false, message: "Failed to fetch notifications" });
  }
};

// Mark single notification as read
export const markNotificationRead = async (req, res) => {
  try {
    const userId = req.user?._id;
    const { id } = req.params;

    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const notification = await Notification.findOne({ _id: id, user: userId });
    if (!notification) {
      return res.status(404).json({ success: false, message: "Notification not found" });
    }

    notification.isRead = true;
    await notification.save();

    return res.json({ success: true, notification });
  } catch (err) {
    console.error("markNotificationRead error:", err);
    return res.status(500).json({ success: false, message: "Failed to update notification" });
  }
};

// Mark all user notifications as read
export const markAllNotificationsRead = async (req, res) => {
  try {
    const userId = req.user?._id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    await Notification.updateMany({ user: userId, isRead: false }, { $set: { isRead: true } });

    return res.json({ success: true });
  } catch (err) {
    console.error("markAllNotificationsRead error:", err);
    return res.status(500).json({ success: false, message: "Failed to update notifications" });
  }
};
