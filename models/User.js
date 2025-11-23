const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true }, // @username
  nickname: { type: String, default: '' }, // Имя (Ник)
  password: { type: String, required: true },
  avatar: { type: String, default: '' },
  bio: { type: String, default: 'Информация не указана' },
  birthDate: { type: String, default: '' },
  blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // ЧС
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', UserSchema);