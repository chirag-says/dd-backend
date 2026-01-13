import mongoose from "mongoose";

const conversationSchema = new mongoose.Schema(
  {
    // Participants in the conversation
    participants: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
      },
    ],
    // Property this conversation is about
    property: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Property",
      required: true,
    },
    // Last message for preview
    lastMessage: {
      text: String,
      sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
      createdAt: Date,
    },
    // Unread count per user
    unreadCount: {
      type: Map,
      of: Number,
      default: {},
    },
    // Is conversation active
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);

// Index for faster queries
conversationSchema.index({ participants: 1 });
conversationSchema.index({ property: 1 });
conversationSchema.index({ updatedAt: -1 });

const Conversation = mongoose.model("Conversation", conversationSchema);
export default Conversation;
