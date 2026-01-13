import Conversation from "../models/Conversation.js";
import Message from "../models/Message.js";
import Property from "../models/Property.js";
import User from "../models/userModel.js";

// Start or get existing conversation
export const startConversation = async (req, res) => {
  try {
    let { propertyId, ownerId } = req.body;
    // Use _id as the primary, fallback to id for special cases like agent/owner
    const buyerId = req.user._id || req.user.id;

    console.log("Start conversation request:", { propertyId, ownerId, buyerId });

    // Validate property exists and get owner if not provided
    const property = await Property.findById(propertyId).populate("owner", "_id name email");
    if (!property) {
      return res.status(404).json({ success: false, message: "Property not found" });
    }

    // If ownerId is not provided, try to get it from the property
    if (!ownerId) {
      ownerId = property.owner?._id?.toString() || property.owner?.toString();
    }

    // Validate ownerId exists
    if (!ownerId) {
      console.error("Property has no owner:", propertyId);
      return res.status(400).json({ 
        success: false, 
        message: "This property has no owner assigned. Cannot start conversation." 
      });
    }

    // Convert to string for comparison
    const ownerIdStr = ownerId.toString();
    const buyerIdStr = buyerId.toString();

    // Can't start conversation with yourself
    if (buyerIdStr === ownerIdStr) {
      return res.status(400).json({ success: false, message: "Cannot start conversation with yourself" });
    }

    // Verify owner exists in database
    const ownerExists = await User.findById(ownerId);
    if (!ownerExists) {
      return res.status(404).json({ success: false, message: "Property owner not found in database" });
    }

    // Check if conversation already exists
    let conversation = await Conversation.findOne({
      participants: { $all: [buyerIdStr, ownerIdStr] },
      property: propertyId,
    });

    if (conversation) {
      // Return existing conversation
      await conversation.populate([
        { path: "participants", select: "name email profileImage" },
        { path: "property", select: "title images address price" },
      ]);
      return res.json({ success: true, conversation, isNew: false });
    }

    // Create new conversation with proper unreadCount initialization
    const unreadCountObj = {};
    unreadCountObj[ownerIdStr] = 0;
    unreadCountObj[buyerIdStr] = 0;

    conversation = new Conversation({
      participants: [buyerIdStr, ownerIdStr],
      property: propertyId,
      unreadCount: unreadCountObj,
    });

    await conversation.save();
    await conversation.populate([
      { path: "participants", select: "name email profileImage" },
      { path: "property", select: "title images address price owner" },
    ]);

    console.log("Conversation created successfully:", conversation._id);
    res.status(201).json({ success: true, conversation, isNew: true });
  } catch (error) {
    console.error("Start conversation error:", error);
    res.status(500).json({ success: false, message: "Failed to start conversation", error: error.message });
  }
};

// Get all conversations for a user
export const getConversations = async (req, res) => {
  try {
    const userId = (req.user._id || req.user.id).toString();

    const conversations = await Conversation.find({
      participants: userId,
      isActive: true,
    })
      .populate("participants", "name email profileImage")
      .populate("property", "title images address price propertyTypeName owner")
      .sort({ updatedAt: -1 });

    // Add other participant info and unread count
    const formattedConversations = conversations.map((conv) => {
      const otherParticipant = conv.participants.find(
        (p) => p._id.toString() !== userId
      );

      const propertyOwner = conv.property?.owner;
      const propertyOwnerId =
        typeof propertyOwner === "string" || !propertyOwner
          ? propertyOwner?.toString?.()
          : propertyOwner._id?.toString?.();

      const isOwner = propertyOwnerId === userId;

      return {
        ...conv.toObject(),
        otherParticipant,
        myUnreadCount: conv.unreadCount.get(userId) || 0,
        isOwner,
      };
    });

    res.json({ success: true, conversations: formattedConversations });
  } catch (error) {
    console.error("Get conversations error:", error);
    res.status(500).json({ success: false, message: "Failed to get conversations" });
  }
};

// Get messages for a conversation
export const getMessages = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = (req.user._id || req.user.id).toString();
    const { page = 1, limit = 50 } = req.query;

    // Verify user is participant
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ success: false, message: "Conversation not found" });
    }

    if (!conversation.participants.map(p => p.toString()).includes(userId)) {
      return res.status(403).json({ success: false, message: "Not authorized" });
    }

    const messages = await Message.find({
      conversation: conversationId,
      isDeleted: false,
    })
      .populate("sender", "name email profileImage")
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    // Mark messages as read
    await Message.updateMany(
      {
        conversation: conversationId,
        sender: { $ne: userId },
        "readBy.user": { $ne: userId },
      },
      {
        $push: { readBy: { user: userId, readAt: new Date() } },
      }
    );

    // Reset unread count for this user
    conversation.unreadCount.set(userId, 0);
    await conversation.save();

    res.json({ success: true, messages: messages.reverse() });
  } catch (error) {
    console.error("Get messages error:", error);
    res.status(500).json({ success: false, message: "Failed to get messages" });
  }
};

// Send a message
export const sendMessage = async (req, res) => {
  try {
    const { conversationId, text, messageType = "text" } = req.body;
    const senderId = (req.user._id || req.user.id).toString();

    // Verify conversation and user is participant
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ success: false, message: "Conversation not found" });
    }

    if (!conversation.participants.map(p => p.toString()).includes(senderId)) {
      return res.status(403).json({ success: false, message: "Not authorized" });
    }

    // Create message
    const message = new Message({
      conversation: conversationId,
      sender: senderId,
      text,
      messageType,
      readBy: [{ user: senderId, readAt: new Date() }],
    });

    await message.save();
    await message.populate("sender", "name email profileImage");

    // Update conversation
    conversation.lastMessage = {
      text,
      sender: senderId,
      createdAt: new Date(),
    };

    // Increment unread count for other participants
    conversation.participants.forEach((participantId) => {
      if (participantId.toString() !== senderId) {
        const currentCount = conversation.unreadCount.get(participantId.toString()) || 0;
        conversation.unreadCount.set(participantId.toString(), currentCount + 1);
      }
    });

    await conversation.save();

    res.status(201).json({ success: true, message });
  } catch (error) {
    console.error("Send message error:", error);
    res.status(500).json({ success: false, message: "Failed to send message" });
  }
};

// Get unread message count
export const getUnreadCount = async (req, res) => {
  try {
    const userId = (req.user._id || req.user.id).toString();

    const conversations = await Conversation.find({
      participants: userId,
      isActive: true,
    });

    let totalUnread = 0;
    conversations.forEach((conv) => {
      totalUnread += conv.unreadCount.get(userId) || 0;
    });

    res.json({ success: true, unreadCount: totalUnread });
  } catch (error) {
    console.error("Get unread count error:", error);
    res.status(500).json({ success: false, message: "Failed to get unread count" });
  }
};

// Delete/Archive conversation
export const deleteConversation = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = (req.user._id || req.user.id).toString();

    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ success: false, message: "Conversation not found" });
    }

    if (!conversation.participants.map(p => p.toString()).includes(userId)) {
      return res.status(403).json({ success: false, message: "Not authorized" });
    }

    // Soft delete - just mark as inactive
    conversation.isActive = false;
    await conversation.save();

    res.json({ success: true, message: "Conversation archived" });
  } catch (error) {
    console.error("Delete conversation error:", error);
    res.status(500).json({ success: false, message: "Failed to delete conversation" });
  }
};
