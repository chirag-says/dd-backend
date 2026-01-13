import mongoose from "mongoose";

const messageSchema = new mongoose.Schema(
  {
    // Conversation this message belongs to
    conversation: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Conversation",
      required: true,
    },
    // Sender of the message
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    // Message content
    text: {
      type: String,
      required: true,
      trim: true,
    },
    // Message type (supports special system actions like visit requests)
    messageType: {
      type: String,
      enum: ["text", "image", "file", "system", "visit_request", "visit_confirmation"],
      default: "text",
    },
    // For file/image messages
    attachments: [
      {
        url: String,
        type: String, // image, document, etc.
        name: String,
      },
    ],
    // Read status
    readBy: [
      {
        user: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        readAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    // Is message deleted
    isDeleted: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

// Index for faster queries
messageSchema.index({ conversation: 1, createdAt: -1 });
messageSchema.index({ sender: 1 });

const Message = mongoose.model("Message", messageSchema);
export default Message;
