const mongoose = require('mongoose');

const ChatSchema = new mongoose.Schema({
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  isGroup: { type: Boolean, default: false },
  title: { type: String, default: '' }, // Название группы
  groupAvatar: { type: String, default: '' },
  admin: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Создатель
  lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' }
}, { timestamps: true });

module.exports = mongoose.model('Chat', ChatSchema);