require('dotenv').config();
const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const cors = require('cors');
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// --- FIREBASE ADMIN (ДЛЯ ПУШЕЙ) ---
const admin = require('firebase-admin');

// ПОПЫТКА ПОДКЛЮЧИТЬ ФАЙЛ КЛЮЧА
// Если вы еще не скачали файл, сервер не упадет, но пуши работать не будут
try {
    const serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    console.log("✅ Firebase Admin Initialized");
} catch (e) {
    console.log("⚠️ ОШИБКА FIREBASE: Файл serviceAccountKey.json не найден. Пуши не будут работать.");
}

// Библиотеки для Cloudinary
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Импорт моделей
const User = require('./models/User');
const Chat = require('./models/Chat');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 5000;

app.set('trust proxy', 1);

app.use(cors({ 
    origin: "*", 
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false
}));
app.use(express.json());

// --- НАСТРОЙКА CLOUDINARY ---
cloudinary.config({
  cloud_name: 'dr4cu91pz',
  api_key: '472476498657853',
  api_secret: 'NDq3J1IFglDPrl7uMohWRMJKh1c'
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'grem_messenger',
    allowed_formats: ['jpg', 'png', 'jpeg', 'webm', 'mp3', 'wav', 'ogg'],
    resource_type: 'auto'
  },
});

const upload = multer({ storage });

const io = new Server(server, { 
    cors: { origin: "*", methods: ["GET", "POST"], credentials: false } 
});

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/grem_messenger';

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected Successfully'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

app.get('/', (req, res) => res.send('Grem Server Running YEA'));

// ==========================================
// API ROUTES
// ==========================================

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('No file');
  res.json({ url: req.file.path, type: req.file.mimetype });
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });

    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: 'Этот логин уже занят' });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const defaultAvatar = `https://ui-avatars.com/api/?name=${username}&background=7c3aed&color=fff&size=128`;
    
    const user = await User.create({ username, nickname: username, password: hashedPassword, avatar: defaultAvatar });
    const token = jwt.sign({ id: user._id }, 'secret_key'); 
    res.json({ user, token });
  } catch (e) { res.status(500).json({ error: "Ошибка при создании пользователя" }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'Пользователь не найден' });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Неверный пароль' });
    
    const token = jwt.sign({ id: user._id }, 'secret_key');
    res.json({ user, token });
  } catch (e) { res.status(500).json({ error: "Ошибка входа" }); }
});

app.put('/api/user/update', async (req, res) => {
  try {
    const { userId, username, ...updates } = req.body;
    if (username) {
        const existing = await User.findOne({ username });
        if (existing && existing._id.toString() !== userId) return res.status(400).json({ error: 'Логин занят' });
        updates.username = username;
    }
    const user = await User.findByIdAndUpdate(userId, updates, { new: true }).select('-password');
    io.emit('user:updated', user);
    res.json(user);
  } catch (e) { res.status(500).json({ error: 'Ошибка обновления' }); }
});

app.get('/api/search', async (req, res) => {
  const { username } = req.query;
  if(!username) return res.json([]);
  try {
      const users = await User.find({ 
        $or: [{ username: { $regex: username, $options: 'i' } }, { nickname: { $regex: username, $options: 'i' } }]
      }).select('-password');
      res.json(users);
  } catch (e) { res.json([]); }
});

app.post('/api/group/create', async (req, res) => {
    try {
        const { title, adminId, memberIds, avatar } = req.body;
        const allMembers = [...new Set([adminId, ...memberIds])];
        const chat = await Chat.create({
            isGroup: true, title, admin: adminId, members: allMembers,
            groupAvatar: avatar || `https://ui-avatars.com/api/?name=${title}&background=purple&color=fff`
        });
        allMembers.forEach(mid => { const sId = onlineUsers.get(mid.toString()); if(sId) io.to(sId).emit('chat:update_list'); });
        res.json(chat);
    } catch(e) { res.status(500).json({error: e.message}); }
});

app.post('/api/user/block', async (req, res) => {
    try { await User.findByIdAndUpdate(req.body.userId, { $addToSet: { blockedUsers: req.body.blockId } }); res.json({ success: true }); } catch(e) { res.status(500).send(e.message); }
});

// ==========================================
// SOCKET.IO
// ==========================================
let onlineUsers = new Map();

io.on('connection', (socket) => {
  
  socket.on('join', async (userId) => {
    if(!userId) return;
    onlineUsers.set(userId, socket.id);
    await User.findByIdAndUpdate(userId, { isOnline: true });
    io.emit('user:status_change', { userId, isOnline: true, lastSeen: null });
  });

  // === СОХРАНЕНИЕ ТОКЕНА УВЕДОМЛЕНИЙ С ТЕЛЕФОНА ===
  socket.on('user:push_token', async ({ userId, token }) => {
      if(!userId || !token) return;
      try {
          // Сохраняем токен в базу. Нужно убедиться, что в модели User есть поле pushToken (String)
          await User.findByIdAndUpdate(userId, { pushToken: token });
          console.log(`📲 Push Token saved for ${userId}`);
      } catch(e) { console.error("Token save error", e); }
  });

  socket.on('get_chats', async (userId) => {
    try {
        const chats = await Chat.find({ members: userId })
            .populate('members', 'username nickname avatar isOnline lastSeen')
            .populate('lastMessage')
            .sort({ updatedAt: -1 });
        socket.emit('chats_list', chats);
    } catch(e){}
  });

  socket.on('chat:get_history', async ({ chatId }) => {
    try { 
        const messages = await Message.find({ chatId }).sort({ createdAt: 1 }); 
        socket.emit('chat:history', { chatId, messages }); 
    } catch(e){}
  });

  socket.on('chat:read', async ({ chatId, userId }) => {
     try {
         await Message.updateMany({ chatId: chatId, sender: { $ne: userId }, readBy: { $ne: userId } }, { $addToSet: { readBy: userId } });
         io.to(chatId).emit('message:read', { chatId, userId }); // Broadcast to room logic needed or iterate
         // Упрощенная логика для списка (можно оптимизировать через комнаты socket.join(chatId))
         const chat = await Chat.findById(chatId);
         if(chat) {
             chat.members.forEach(m => { 
                 const sId = onlineUsers.get(m.toString()); 
                 if(sId) io.to(sId).emit('message:read', { chatId, userId }); 
             });
         }
     } catch(e){}
  });

  socket.on('typing', ({ chatId, userId, isTyping }) => socket.broadcast.emit('typing', { chatId, userId, isTyping }));
  socket.on('recording', ({ chatId, userId, isRecording }) => socket.broadcast.emit('recording', { chatId, userId, isRecording }));
  socket.on('user:profile_update', (userData) => socket.broadcast.emit('user:updated', userData));

  // === ОТПРАВКА СООБЩЕНИЯ + ПУШ ===
  socket.on('message:send', async (data) => {
    try {
      const { senderId, receiverId, text, fileUrl, type, isGroup, chatId: existingChatId } = data;
      
      let chat;
      if (existingChatId) { 
          chat = await Chat.findById(existingChatId); 
      } else if (!isGroup) {
          if (senderId === receiverId) { 
              chat = await Chat.findOne({ members: [senderId], isGroup: false, members: { $size: 1 } }); 
              if(!chat) chat = await Chat.create({ members: [senderId] }); 
          } else { 
              chat = await Chat.findOne({ members: { $all: [senderId, receiverId], $size: 2 }, isGroup: false }); 
              if (!chat) chat = await Chat.create({ members: [senderId, receiverId] }); 
          }
      }
      
      if (!chat) return;

      const newMessage = await Message.create({ chatId: chat._id, sender: senderId, text, fileUrl, type });
      await Chat.findByIdAndUpdate(chat._id, { lastMessage: newMessage._id });
      
      // Отправка сокетов и ПУШЕЙ
      chat.members.forEach(async (memberId) => { 
          const mIdString = memberId.toString();
          
          // 1. Отправляем в сокет (если онлайн)
          const sId = onlineUsers.get(mIdString); 
          if (sId) { 
              io.to(sId).emit('message:new', { ...newMessage._doc, chatId: chat._id, receiverId: receiverId }); 
              io.to(sId).emit('chat:update_list'); 
          }

          // 2. Отправляем PUSH (если это не я сам)
          if (mIdString !== senderId) {
              try {
                  const recipient = await User.findById(mIdString);
                  if (recipient && recipient.pushToken) {
                      const pushTitle = isGroup ? `Группа: ${chat.title}` : 'Новое сообщение';
                      const pushBody = type === 'text' ? text : (type === 'image' ? '📷 Фото' : '🎤 Голосовое');
                      
                      await admin.messaging().send({
                          token: recipient.pushToken,
                          notification: {
                              title: pushTitle,
                              body: pushBody,
                          },
                          data: {
                              chatId: chat._id.toString(), // Чтобы открывать чат по клику (нужна логика на клиенте)
                          },
                          android: {
                              priority: 'high',
                              notification: {
                                  sound: 'default',
                                  channelId: 'default'
                              }
                          }
                      });
                      console.log(`🚀 Push sent to ${recipient.username}`);
                  }
              } catch (pushErr) {
                  console.error("Push Error:", pushErr.message);
                  // Если токен устарел, можно его удалить:
                  if (pushErr.code === 'messaging/registration-token-not-registered') {
                      await User.findByIdAndUpdate(mIdString, { pushToken: null });
                  }
              }
          }
      });
    } catch (e) { console.error(e); }
  });

  socket.on('disconnect', async () => {
    let uid;
    for (let [key, val] of onlineUsers.entries()) { if(val === socket.id) uid = key; }
    if (uid) { 
        onlineUsers.delete(uid); 
        const now = new Date(); 
        await User.findByIdAndUpdate(uid, { isOnline: false, lastSeen: now }); 
        io.emit('user:status_change', { userId: uid, isOnline: false, lastSeen: now }); 
    }
  });

  socket.on('call:start', d => { const s = onlineUsers.get(d.receiverId); if(s) io.to(s).emit('call:incoming', d); });
  socket.on('call:answer', d => { const s = onlineUsers.get(d.callerId); if(s) io.to(s).emit('call:answered', d); });
  socket.on('ice-candidate', d => { const s = onlineUsers.get(d.targetId); if(s) io.to(s).emit('ice-candidate', d); });
});

server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));