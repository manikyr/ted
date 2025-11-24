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

const User = require('./models/User');
const Chat = require('./models/Chat');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 5000;

// --- ИСПРАВЛЕННЫЙ CORS ---
// Разрешаем всем (*) и отключаем credentials, чтобы телефоны не блокировали запросы
app.use(cors({ 
    origin: "*", 
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false // Важно: false при origin "*"
}));
app.use(express.json());

// Папка для загрузок
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static(uploadDir));

// --- ИСПРАВЛЕННЫЙ SOCKET.IO ---
const io = new Server(server, { 
    cors: { 
        origin: "*", 
        methods: ["GET", "POST"],
        credentials: false // Тоже отключаем для совместимости с "*"
    } 
});

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/grem_messenger_v3';

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

app.get('/', (req, res) => {
  res.send('Grem Messenger Server is Running! 🚀');
});

// --- API ROUTES ---

app.post('/api/register', async (req, res) => {
  try {
    const { nickname, password } = req.body;
    let randomUsername;
    let isUnique = false;
    // Генерируем уникальный юзернейм
    while (!isUnique) {
        const randomId = Math.floor(100000 + Math.random() * 900000);
        randomUsername = `user${randomId}`;
        const existing = await User.findOne({ username: randomUsername });
        if (!existing) isUnique = true;
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    // Аватарка по умолчанию
    const defaultAvatar = `https://ui-avatars.com/api/?name=${nickname}&background=0D8ABC&color=fff&size=128`;
    
    const user = await User.create({ 
        username: randomUsername, 
        nickname, 
        password: hashedPassword, 
        avatar: defaultAvatar 
    });
    
    const token = jwt.sign({ id: user._id }, 'secret_key'); 
    res.json({ user, token });
  } catch (e) { 
      console.error("Register Error:", e);
      res.status(400).json({ error: e.message }); 
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) throw new Error('Пользователь не найден');
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throw new Error('Неверный пароль');
    
    const token = jwt.sign({ id: user._id }, 'secret_key');
    res.json({ user, token });
  } catch (e) { 
      res.status(400).json({ error: e.message }); 
  }
});

app.put('/api/user/update', async (req, res) => {
  try {
    const { userId, username, ...updates } = req.body;
    if (username) {
        const existing = await User.findOne({ username });
        if (existing && existing._id.toString() !== userId) {
            return res.status(400).json({ error: 'Юзернейм занят' });
        }
        updates.username = username;
    }
    const user = await User.findByIdAndUpdate(userId, updates, { new: true }).select('-password');
    res.json(user);
  } catch (e) { res.status(500).json({ error: 'Update Error' }); }
});

app.get('/api/search', async (req, res) => {
  const { username } = req.query;
  if(!username) return res.json([]);
  try {
      const users = await User.find({ 
        $or: [
            { username: { $regex: username, $options: 'i' } }, 
            { nickname: { $regex: username, $options: 'i' } }
        ]
      }).select('-password');
      res.json(users);
  } catch (e) { res.status(500).json([]); }
});

app.post('/api/group/create', async (req, res) => {
    try {
        const { title, adminId, memberIds, avatar } = req.body;
        const allMembers = [...new Set([adminId, ...memberIds])];
        const chat = await Chat.create({
            isGroup: true, title, admin: adminId, members: allMembers,
            groupAvatar: avatar || `https://ui-avatars.com/api/?name=${title}&background=purple&color=fff`
        });
        
        // Оповещаем участников
        allMembers.forEach(mid => {
             const sId = onlineUsers.get(mid.toString());
             if(sId) io.to(sId).emit('chat:update_list'); 
        });
        res.json(chat);
    } catch(e) { res.status(500).json({error: e.message}); }
});

app.post('/api/user/block', async (req, res) => {
    try {
        const { userId, blockId } = req.body;
        await User.findByIdAndUpdate(userId, { $addToSet: { blockedUsers: blockId } });
        res.json({ success: true });
    } catch(e) { res.status(500).send(e.message); }
});

// Настройка Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

app.post('/api/upload', upload.single('file'), (req, res) => {
  if(!req.file) return res.status(400).send('No file');
  const protocol = req.protocol;
  const host = req.get('host');
  // Формируем полный URL к файлу
  res.json({ url: `${protocol}://${host}/uploads/${req.file.filename}`, type: req.file.mimetype });
});

// --- SOCKETS ---
let onlineUsers = new Map(); // userId -> socketId

io.on('connection', (socket) => {
  
  socket.on('join', async (userId) => {
    if(!userId) return;
    onlineUsers.set(userId, socket.id);
    await User.findByIdAndUpdate(userId, { isOnline: true });
    io.emit('user:status_change', { userId, isOnline: true, lastSeen: null });
  });

  socket.on('get_chats', async (userId) => {
    try {
        const chats = await Chat.find({ members: userId })
          .populate('members', 'username nickname avatar isOnline lastSeen')
          .populate('lastMessage')
          .sort({ updatedAt: -1 });
        socket.emit('chats_list', chats);
    } catch(e) { console.error(e); }
  });

  socket.on('chat:get_history', async ({ chatId }) => {
    if(!chatId) return;
    try {
        const messages = await Message.find({ chatId }).sort({ createdAt: 1 });
        socket.emit('chat:history', { chatId, messages });
    } catch(e) {}
  });

  socket.on('chat:read', async ({ chatId, userId }) => {
     try {
         await Message.updateMany(
             { chatId: chatId, sender: { $ne: userId }, readBy: { $ne: userId } },
             { $addToSet: { readBy: userId } }
         );
         
         const chat = await Chat.findById(chatId);
         if(chat) {
             chat.members.forEach(m => {
                 const sId = onlineUsers.get(m.toString());
                 if(sId) io.to(sId).emit('messages:read_update', { chatId, readerId: userId });
             });
         }
     } catch(e) { console.error(e); }
  });

  socket.on('typing', ({ chatId, userId, isTyping }) => {
      socket.broadcast.emit('typing', { chatId, userId, isTyping });
  });

  socket.on('user:profile_update', (userData) => {
      socket.broadcast.emit('user:updated', userData);
  });

  socket.on('recording', ({ chatId, userId, isRecording }) => {
      socket.broadcast.emit('recording', { chatId, userId, isRecording });
  });

  socket.on('message:send', async (data) => {
    try {
      const { senderId, receiverId, text, fileUrl, type, isGroup, chatId: existingChatId } = data;
      let chat;
      
      if (existingChatId) {
          chat = await Chat.findById(existingChatId);
      } else if (!isGroup) {
          // Ищем личный чат
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

      // Отправляем сообщение всем участникам чата, кто онлайн
      chat.members.forEach(memberId => {
        const sId = onlineUsers.get(memberId.toString());
        if (sId) {
          io.to(sId).emit('message:new', { ...newMessage._doc, chatId: chat._id, receiverId: receiverId });
          io.to(sId).emit('chat:update_list'); 
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

  // WebRTC звонки
  socket.on('call:start', d => { const s = onlineUsers.get(d.receiverId); if(s) io.to(s).emit('call:incoming', d); });
  socket.on('call:answer', d => { const s = onlineUsers.get(d.callerId); if(s) io.to(s).emit('call:answered', d); });
  socket.on('ice-candidate', d => { const s = onlineUsers.get(d.targetId); if(s) io.to(s).emit('ice-candidate', d); });
});

server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));