// --- START OF FILE index.js ---

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
// --- ИМПОРТ PEER SERVER ---
const { ExpressPeerServer } = require('peer');

// --- FIREBASE ADMIN (ДЛЯ ПУШЕЙ) ---
const admin = require('firebase-admin');

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

// --- НАСТРОЙКА PEER SERVER ---
const peerServer = ExpressPeerServer(server, {
  debug: true,
  path: '/'
});

app.use('/peerjs', peerServer);

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

// ==========================================
// SOCKET.IO
// ==========================================
let onlineUsers = new Map();

io.on('connection', (socket) => {
  
  socket.on('join', async (userId) => {
    if(!userId) return;
    const idStr = userId.toString();
    onlineUsers.set(idStr, socket.id);
    await User.findByIdAndUpdate(userId, { isOnline: true });
    io.emit('user:status_change', { userId, isOnline: true, lastSeen: null });
    console.log(`✅ User connected: ${idStr}`);
  });

  socket.on('user:push_token', async ({ userId, token }) => {
      if(!userId || !token) return;
      try { await User.findByIdAndUpdate(userId, { pushToken: token }); } catch(e) {}
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
        socket.emit('message:history', { chatId, history: messages }); // Исправлено событие
    } catch(e){}
  });

  socket.on('chat:read', async ({ chatId, userId }) => {
     try {
         await Message.updateMany({ chatId: chatId, sender: { $ne: userId }, readBy: { $ne: userId } }, { $addToSet: { readBy: userId } });
         const chat = await Chat.findById(chatId);
         if(chat) {
             chat.members.forEach(m => { 
                 const sId = onlineUsers.get(m.toString()); 
                 if(sId) io.to(sId).emit('messages:read', { chatId, userId }); // Исправлено событие
             });
         }
     } catch(e){}
  });

  socket.on('user:update_profile', (userData) => socket.broadcast.emit('user:status_change', { userId: userData._id, ...userData })); // Исправлено

  // === ОТПРАВКА СООБЩЕНИЯ + PUSH ===
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
      
      chat.members.forEach(async (memberId) => { 
          const mIdString = memberId.toString();
          const sId = onlineUsers.get(mIdString); 
          
          if (sId) { 
              io.to(sId).emit('message:new', { ...newMessage._doc, chatId: chat._id, receiverId: receiverId }); 
              // io.to(sId).emit('chats_list'); // Не нужно, клиент сам обновит список
          }

          // PUSH
          if (mIdString !== senderId) {
              try {
                  const recipient = await User.findById(mIdString);
                  if (recipient && recipient.pushToken) {
                      await admin.messaging().send({
                          token: recipient.pushToken,
                          notification: {
                              title: isGroup ? `Группа: ${chat.title}` : 'Новое сообщение',
                              body: type === 'text' ? text : 'Вложение',
                          },
                          data: { chatId: chat._id.toString() },
                          android: { priority: 'high', notification: { sound: 'default' } }
                      });
                  }
              } catch (e) {}
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
});

server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));