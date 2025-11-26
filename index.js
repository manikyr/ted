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
const { ExpressPeerServer } = require('peer');

// --- FIREBASE ADMIN (PUSH NOTIFICATIONS) ---
const admin = require('firebase-admin');

try {
    // Скачайте этот файл из Firebase Console -> Project Settings -> Service Accounts
    const serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    console.log("✅ Firebase Admin Initialized");
} catch (e) {
    console.log("⚠️ ПРЕДУПРЕЖДЕНИЕ: Файл serviceAccountKey.json не найден. Пуш-уведомления на телефон не будут работать.");
}

// --- CLOUDINARY (ФАЙЛЫ) ---
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Настройте свои ключи Cloudinary
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

// --- MODELS ---
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
    credentials: true 
}));
app.use(express.json());

// --- SOCKET.IO ---
const io = new Server(server, { 
    cors: { origin: "*", methods: ["GET", "POST"], credentials: true },
    transports: ['websocket', 'polling']
});

// --- PEER SERVER (ЗВОНКИ БЕЗ VPN) ---
const peerServer = ExpressPeerServer(server, {
  debug: true,
  path: '/',
  allow_discovery: true
});

app.use('/peerjs', peerServer);

// --- DB ---
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/grem_messenger';
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

app.get('/', (req, res) => res.send('Grem Server Running'));

// --- REST API ---
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('No file');
  res.json({ url: req.file.path, type: req.file.mimetype });
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Заполните поля' });
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ error: 'Логин занят' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const defaultAvatar = `https://ui-avatars.com/api/?name=${username}&background=7c3aed&color=fff&size=128`;
    const user = await User.create({ username, nickname: username, password: hashedPassword, avatar: defaultAvatar });
    const token = jwt.sign({ id: user._id }, 'secret_key'); 
    res.json({ user, token });
  } catch (e) { res.status(500).json({ error: "Ошибка регистрации" }); }
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
    io.emit('user:updated_data', user);
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

// --- SOCKET LOGIC ---
let onlineUsers = new Map();

io.on('connection', (socket) => {
  
  socket.on('join', async (userId) => {
    if(!userId) return;
    const idStr = userId.toString();
    onlineUsers.set(idStr, socket.id);
    await User.findByIdAndUpdate(userId, { isOnline: true });
    io.emit('user:status_change', { userId, isOnline: true, lastSeen: null });
  });

  // Сохранение токена FCM от мобильного клиента
  socket.on('user:push_token', async ({ userId, token }) => {
      if(!userId || !token) return;
      try { 
          await User.findByIdAndUpdate(userId, { pushToken: token }); 
          console.log(`📲 Token saved for ${userId}`);
      } catch(e) {}
  });

  socket.on('get_chats', async (userId) => {
    try {
        const chats = await Chat.find({ members: userId })
            .populate('members', 'username nickname avatar isOnline lastSeen birthDay birthMonth birthYear bio')
            .populate('lastMessage')
            .sort({ updatedAt: -1 });
        socket.emit('chats_list', chats);
    } catch(e){}
  });

  socket.on('chat:get_history', async ({ chatId }) => {
    try { 
        const messages = await Message.find({ chatId }).sort({ createdAt: 1 }); 
        socket.emit('message:history', { chatId, history: messages }); 
    } catch(e){}
  });

  socket.on('chat:read', async ({ chatId, userId }) => {
     try {
         await Message.updateMany({ chatId: chatId, sender: { $ne: userId }, readBy: { $ne: userId } }, { $addToSet: { readBy: userId } });
         const chat = await Chat.findById(chatId);
         if(chat) {
             chat.members.forEach(m => { 
                 const sId = onlineUsers.get(m.toString()); 
                 if(sId) io.to(sId).emit('messages:read', { chatId, userId }); 
             });
         }
     } catch(e){}
  });

  socket.on('user:update_profile', (userData) => socket.broadcast.emit('user:updated_data', userData));

  // --- CALLS ---
  socket.on('call:connected', ({ to }) => {
      const sId = onlineUsers.get(to);
      if (sId) io.to(sId).emit('call:connected_confirmed');
  });
  socket.on('call:end', ({ to, reason }) => {
      const sId = onlineUsers.get(to);
      if (sId) io.to(sId).emit('call:ended_remote', { reason });
  });
  socket.on('call:toggle_media', ({ to, type, status }) => {
      const sId = onlineUsers.get(to);
      if (sId) io.to(sId).emit('call:remote_media_change', { type, status });
  });

  // --- MESSAGES & PUSH ---
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
      
      // Отправка всем участникам
      chat.members.forEach(async (memberId) => { 
          const mIdString = memberId.toString();
          const sId = onlineUsers.get(mIdString); 
          
          // Отправка в сокет (если онлайн)
          if (sId) { 
              io.to(sId).emit('message:new', { ...newMessage._doc, chatId: chat._id, receiverId: receiverId }); 
          }

          // Отправка PUSH (если оффлайн или свернут) - ТОЛЬКО ПОЛУЧАТЕЛЮ
          if (mIdString !== senderId) {
              try {
                  const recipient = await User.findById(mIdString);
                  if (recipient && recipient.pushToken) {
                      await admin.messaging().send({
                          token: recipient.pushToken,
                          notification: {
                              title: 'Новое сообщение',
                              body: type === 'text' ? text : (type === 'audio' ? '🎤 Голосовое сообщение' : '📷 Фотография'),
                          },
                          data: { 
                              chatId: chat._id.toString(),
                              type: 'message'
                          },
                          android: { priority: 'high', notification: { sound: 'default', clickAction: 'FLUTTER_NOTIFICATION_CLICK' } }
                      });
                      console.log(`🔔 Push sent to ${recipient.username}`);
                  }
              } catch (e) {
                  // console.error("Push error:", e.message);
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
});

server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));