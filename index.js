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
// Импорт PeerServer для звонков внутри вашего бэкенда
const { ExpressPeerServer } = require('peer');

// --- FIREBASE ADMIN (ДЛЯ ПУШ-УВЕДОМЛЕНИЙ) ---
const admin = require('firebase-admin');

try {
    const serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
    console.log("✅ Firebase Admin Initialized");
} catch (e) {
    console.log("⚠️ ОШИБКА FIREBASE: Файл serviceAccountKey.json не найден или некорректен. Пуши не будут работать.");
}

// Библиотеки для Cloudinary (Файлы)
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Импорт моделей (Убедитесь, что файлы существуют в папке models)
const User = require('./models/User');
const Chat = require('./models/Chat');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 5000;

app.set('trust proxy', 1);

// Разрешаем запросы с любых источников (для мобилок и веба)
app.use(cors({ 
    origin: "*", 
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false
}));
app.use(express.json());

// --- НАСТРОЙКА PEER SERVER (ЗВОНКИ) ---
// Это создает путь /peerjs на вашем сервере, к которому подключается клиент
const peerServer = ExpressPeerServer(server, {
  debug: true,
  path: '/',
  allow_discovery: true
});

app.use('/peerjs', peerServer);

// --- НАСТРОЙКА CLOUDINARY (ФОТО/АУДИО) ---
cloudinary.config({
  cloud_name: 'dr4cu91pz', // Ваши данные
  api_key: '472476498657853',
  api_secret: 'NDq3J1IFglDPrl7uMohWRMJKh1c'
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'grem_messenger',
    allowed_formats: ['jpg', 'png', 'jpeg', 'webm', 'mp3', 'wav', 'ogg'],
    resource_type: 'auto' // Автоматически определять фото или аудио
  },
});

const upload = multer({ storage });

// --- НАСТРОЙКА SOCKET.IO ---
const io = new Server(server, { 
    cors: { origin: "*", methods: ["GET", "POST"], credentials: false },
    transports: ['websocket', 'polling'] // Поддержка обоих транспортов
});

// --- ПОДКЛЮЧЕНИЕ К БД ---
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/grem_messenger';

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected Successfully'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

app.get('/', (req, res) => res.send('Talk Server is Running 🚀'));

// ==========================================
// API ROUTES (REST)
// ==========================================

// Загрузка файлов
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  res.json({ url: req.file.path, type: req.file.mimetype });
});

// Регистрация
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

// Вход
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

// Обновление профиля (через HTTP, дублируется через сокет для реал-тайма)
app.put('/api/user/update', async (req, res) => {
  try {
    const { userId, username, ...updates } = req.body;
    if (username) {
        const existing = await User.findOne({ username });
        if (existing && existing._id.toString() !== userId) return res.status(400).json({ error: 'Логин занят' });
        updates.username = username;
    }
    const user = await User.findByIdAndUpdate(userId, updates, { new: true }).select('-password');
    // Сообщаем всем через сокет, что юзер обновился
    io.emit('user:updated_data', user);
    res.json(user);
  } catch (e) { res.status(500).json({ error: 'Ошибка обновления' }); }
});

// Поиск пользователей
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
// SOCKET.IO LOGIC
// ==========================================
let onlineUsers = new Map(); // Хранит соответствие userId -> socketId

io.on('connection', (socket) => {
  
  // Пользователь зашел в приложение
  socket.on('join', async (userId) => {
    if(!userId) return;
    const idStr = userId.toString();
    onlineUsers.set(idStr, socket.id);
    
    // Обновляем статус в БД
    await User.findByIdAndUpdate(userId, { isOnline: true });
    
    // Сообщаем всем, что он онлайн
    io.emit('user:status_change', { userId, isOnline: true, lastSeen: null });
    console.log(`✅ User connected: ${idStr}`);
  });

  // Сохранение токена для пушей (от мобильного приложения)
  socket.on('user:push_token', async ({ userId, token }) => {
      if(!userId || !token) return;
      try {
          await User.findByIdAndUpdate(userId, { pushToken: token });
          console.log(`📲 Token saved for ${userId}`);
      } catch(e) { console.error("Token save error", e); }
  });

  // Получение списка чатов
  socket.on('get_chats', async (userId) => {
    try {
        const chats = await Chat.find({ members: userId })
            .populate('members', 'username nickname avatar isOnline lastSeen birthDay birthMonth birthYear bio') // Загружаем все поля профиля
            .populate('lastMessage')
            .sort({ updatedAt: -1 });
        socket.emit('chats_list', chats);
    } catch(e){}
  });

  // Получение истории сообщений
  socket.on('chat:get_history', async ({ chatId }) => {
    try { 
        const messages = await Message.find({ chatId }).sort({ createdAt: 1 }); 
        socket.emit('message:history', { chatId, history: messages }); 
    } catch(e){}
  });

  // Отметка "Прочитано"
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

  // Обновление профиля в реальном времени
  socket.on('user:update_profile', (userData) => {
      // Сообщаем всем клиентам обновить инфо об этом юзере (аватарка, имя и т.д.)
      socket.broadcast.emit('user:updated_data', userData);
  });

  // === ЛОГИКА ЗВОНКОВ (Синхронизация) ===

  // 1. Соединение установлено (собеседник взял трубку)
  socket.on('call:connected', ({ to }) => {
      const callerSocketId = onlineUsers.get(to);
      // Отправляем звонящему подтверждение, чтобы запустить таймер
      if (callerSocketId) io.to(callerSocketId).emit('call:connected_confirmed');
  });

  // 2. Завершение звонка
  socket.on('call:end', ({ to, reason }) => {
      const targetSocketId = onlineUsers.get(to);
      // Говорим собеседнику закрыть окно звонка
      if (targetSocketId) io.to(targetSocketId).emit('call:ended_remote', { reason });
  });

  // 3. Переключение микрофона/камеры (опционально, для иконок)
  socket.on('call:toggle_media', ({ to, type, status }) => {
      const targetSocketId = onlineUsers.get(to);
      if (targetSocketId) io.to(targetSocketId).emit('call:remote_media_change', { type, status });
  });

  // === ОТПРАВКА СООБЩЕНИЯ ===
  socket.on('message:send', async (data) => {
    try {
      const { senderId, receiverId, text, fileUrl, type, isGroup, chatId: existingChatId } = data;
      
      let chat;
      // Если чат уже есть
      if (existingChatId) { 
          chat = await Chat.findById(existingChatId); 
      } 
      // Если чата нет (первое сообщение)
      else if (!isGroup) {
          // Проверяем, есть ли чат с такими участниками
          chat = await Chat.findOne({ members: { $all: [senderId, receiverId], $size: 2 }, isGroup: false }); 
          if (!chat) {
              // Создаем новый чат
              chat = await Chat.create({ members: [senderId, receiverId] }); 
          }
      }
      
      if (!chat) return;

      // Создаем сообщение в БД
      const newMessage = await Message.create({ chatId: chat._id, sender: senderId, text, fileUrl, type });
      
      // Обновляем последнее сообщение в чате
      await Chat.findByIdAndUpdate(chat._id, { lastMessage: newMessage._id });
      
      // Рассылаем сообщение участникам
      chat.members.forEach(async (memberId) => { 
          const mIdString = memberId.toString();
          const sId = onlineUsers.get(mIdString); 
          
          if (sId) { 
              // Отправляем само сообщение
              io.to(sId).emit('message:new', { ...newMessage._doc, chatId: chat._id, receiverId: receiverId }); 
          }

          // Отправляем PUSH уведомление (через Firebase), если получатель не отправитель
          if (mIdString !== senderId) {
              try {
                  const recipient = await User.findById(mIdString);
                  if (recipient && recipient.pushToken) {
                      await admin.messaging().send({
                          token: recipient.pushToken,
                          notification: {
                              title: isGroup ? `Группа: ${chat.title}` : 'Новое сообщение',
                              body: type === 'text' ? text : (type === 'audio' ? '🎤 Голосовое' : '📷 Фото'),
                          },
                          data: { chatId: chat._id.toString() },
                          android: { priority: 'high', notification: { sound: 'default' } }
                      });
                  }
              } catch (e) { 
                  // Ошибка пуша не должна ломать чат
                  // console.error("Push Error:", e.message); 
              }
          }
      });
    } catch (e) { console.error(e); }
  });

  // Отключение пользователя
  socket.on('disconnect', async () => {
    let uid;
    // Ищем userId по socketId
    for (let [key, val] of onlineUsers.entries()) { if(val === socket.id) uid = key; }
    
    if (uid) { 
        onlineUsers.delete(uid); 
        const now = new Date(); 
        // Обновляем статус на offline и ставим время выхода
        await User.findByIdAndUpdate(uid, { isOnline: false, lastSeen: now }); 
        io.emit('user:status_change', { userId: uid, isOnline: false, lastSeen: now }); 
    }
  });
});

// Запуск сервера
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));