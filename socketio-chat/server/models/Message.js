const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  content: { type: String, required: true },
  username: { type: String, required: true },
  room: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true },
  roomName: { type: String, required: true }, // Added for easier reference
  time: { type: Date, default: Date.now },
  file: {
    url: String,
    name: String,
    type: String,
    size: Number,
    deleted: { type: Boolean, default: false } // Track if file is deleted
  },
  readBy: [{ type: String }], // Store usernames directly
  deletedFor: [{ type: String }] // Store usernames directly
}, { timestamps: true });

module.exports = mongoose.model('Message', messageSchema);