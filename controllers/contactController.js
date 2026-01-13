import ContactInquiry from "../models/ContactInquiry.js";
import User from "../models/userModel.js";

// Create a new contact inquiry (requires logged-in user)
export const createInquiry = async (req, res) => {
  try {
    const userId = req.user._id || req.user.id;
    const { subject, message, category } = req.body;

    if (!subject || !message) {
      return res.status(400).json({
        success: false,
        message: "Subject and message are required",
      });
    }

    // Get user details for snapshot
    const user = await User.findById(userId).select("name email phone profileImage");
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Create inquiry with user snapshot
    const inquiry = new ContactInquiry({
      user: userId,
      userSnapshot: {
        name: user.name,
        email: user.email,
        phone: user.phone || "",
        profileImage: user.profileImage || "",
      },
      subject,
      message,
      category: category || "general",
    });

    await inquiry.save();

    res.status(201).json({
      success: true,
      message: "Your inquiry has been submitted successfully. We'll get back to you soon!",
      inquiry,
    });
  } catch (error) {
    console.error("Create inquiry error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to submit inquiry",
      error: error.message,
    });
  }
};

// Get all inquiries (Admin only)
export const getAllInquiries = async (req, res) => {
  try {
    const { status, priority, category, page = 1, limit = 20, search } = req.query;

    const query = {};

    if (status) query.status = status;
    if (priority) query.priority = priority;
    if (category) query.category = category;

    // Search by subject or message
    if (search) {
      query.$or = [
        { subject: { $regex: search, $options: "i" } },
        { message: { $regex: search, $options: "i" } },
        { "userSnapshot.name": { $regex: search, $options: "i" } },
        { "userSnapshot.email": { $regex: search, $options: "i" } },
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [inquiries, total] = await Promise.all([
      ContactInquiry.find(query)
        .populate("user", "name email phone profileImage")
        .populate("handledBy", "name email")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      ContactInquiry.countDocuments(query),
    ]);

    // Get stats
    const stats = await ContactInquiry.aggregate([
      {
        $group: {
          _id: "$status",
          count: { $sum: 1 },
        },
      },
    ]);

    const unreadCount = await ContactInquiry.countDocuments({ isRead: false });

    res.json({
      success: true,
      inquiries,
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / parseInt(limit)),
        limit: parseInt(limit),
      },
      stats: stats.reduce((acc, s) => ({ ...acc, [s._id]: s.count }), {}),
      unreadCount,
    });
  } catch (error) {
    console.error("Get inquiries error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch inquiries",
      error: error.message,
    });
  }
};

// Get single inquiry by ID (Admin only)
export const getInquiryById = async (req, res) => {
  try {
    const { id } = req.params;

    const inquiry = await ContactInquiry.findById(id)
      .populate("user", "name email phone profileImage createdAt")
      .populate("handledBy", "name email");

    if (!inquiry) {
      return res.status(404).json({
        success: false,
        message: "Inquiry not found",
      });
    }

    // Mark as read
    if (!inquiry.isRead) {
      inquiry.isRead = true;
      await inquiry.save();
    }

    res.json({
      success: true,
      inquiry,
    });
  } catch (error) {
    console.error("Get inquiry error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch inquiry",
      error: error.message,
    });
  }
};

// Update inquiry status/response (Admin only)
export const updateInquiry = async (req, res) => {
  try {
    const { id } = req.params;
    const { status, priority, adminNotes, adminResponse } = req.body;
    const adminId = req.admin?._id;

    const inquiry = await ContactInquiry.findById(id);
    if (!inquiry) {
      return res.status(404).json({
        success: false,
        message: "Inquiry not found",
      });
    }

    // Update fields
    if (status) {
      inquiry.status = status;
      if (status === "resolved" || status === "closed") {
        inquiry.resolvedAt = new Date();
      }
    }

    if (priority) inquiry.priority = priority;
    if (adminNotes !== undefined) inquiry.adminNotes = adminNotes;
    
    if (adminResponse) {
      inquiry.adminResponse = adminResponse;
      inquiry.respondedAt = new Date();
    }

    if (adminId) inquiry.handledBy = adminId;

    await inquiry.save();

    res.json({
      success: true,
      message: "Inquiry updated successfully",
      inquiry,
    });
  } catch (error) {
    console.error("Update inquiry error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update inquiry",
      error: error.message,
    });
  }
};

// Delete inquiry (Admin only)
export const deleteInquiry = async (req, res) => {
  try {
    const { id } = req.params;

    const inquiry = await ContactInquiry.findByIdAndDelete(id);
    if (!inquiry) {
      return res.status(404).json({
        success: false,
        message: "Inquiry not found",
      });
    }

    res.json({
      success: true,
      message: "Inquiry deleted successfully",
    });
  } catch (error) {
    console.error("Delete inquiry error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete inquiry",
      error: error.message,
    });
  }
};

// Mark inquiry as read (Admin only)
export const markAsRead = async (req, res) => {
  try {
    const { id } = req.params;

    const inquiry = await ContactInquiry.findByIdAndUpdate(
      id,
      { isRead: true },
      { new: true }
    );

    if (!inquiry) {
      return res.status(404).json({
        success: false,
        message: "Inquiry not found",
      });
    }

    res.json({
      success: true,
      message: "Marked as read",
      inquiry,
    });
  } catch (error) {
    console.error("Mark as read error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to mark as read",
      error: error.message,
    });
  }
};

// Mark all as read (Admin only)
export const markAllAsRead = async (req, res) => {
  try {
    await ContactInquiry.updateMany({ isRead: false }, { isRead: true });

    res.json({
      success: true,
      message: "All inquiries marked as read",
    });
  } catch (error) {
    console.error("Mark all as read error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to mark all as read",
      error: error.message,
    });
  }
};

// Get user's own inquiries
export const getMyInquiries = async (req, res) => {
  try {
    const userId = req.user._id || req.user.id;

    const inquiries = await ContactInquiry.find({ user: userId })
      .sort({ createdAt: -1 })
      .select("-adminNotes -handledBy");

    res.json({
      success: true,
      inquiries,
    });
  } catch (error) {
    console.error("Get my inquiries error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch your inquiries",
      error: error.message,
    });
  }
};
