// server.js
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const mqtt = require('mqtt');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'chia_khoa_bao_mat_123';
const REFRESH_JWT_SECRET = 'chia_khoa_bao_mat_refresh_123';
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ==========================================
// 1. CÁC API CHO FRONTEND GOI (HTTP)
// ==========================================

// 🟢 API Đăng ký tài khoản
app.post('/api/register', async (req, res) => {
  const { username, password, role = 'user', canViewData = 0 } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (username, password, role, canViewData) VALUES (?, ?, ?, ?)`,
    [username, hashedPassword, role, canViewData],
    (err) => {
      if (err) return res.status(400).json({ message: 'Tài khoản đã tồn tại!' });
      res.json({ message: 'Đăng ký thành công!' });
    }
  );
});

// 🟢 API Đăng nhập (Trả về Token)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: 'Sai tài khoản hoặc mật khẩu!' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, canViewData: user.canViewData },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    const refreshToken = jwt.sign(
      { id: user.id, username: user.username },
      REFRESH_JWT_SECRET,
      { expiresIn: '7d' }
    );

    db.run(`INSERT INTO refresh_tokens (token, userId) VALUES (?, ?)`, [refreshToken, user.id], (err) => {
      if (err) return res.status(500).json({ message: 'Lỗi máy chủ!' });
      res.json({ 
        token, 
        refreshToken, 
        user: { username: user.username, role: user.role, canViewData: Boolean(user.canViewData) } 
      });
    });
  });
});

app.post('/api/refresh-token', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ message: 'Không tìm thấy Refresh Token!' });

  db.get(`SELECT * FROM refresh_tokens WHERE token = ?`, [refreshToken], (err, row) => {
    if (err || !row) return res.status(403).json({ message: 'Refresh Token không hợp lệ hoặc đã bị thu hồi!' });

    jwt.verify(refreshToken, REFRESH_JWT_SECRET, (err, decoded) => {
      if (err) return res.status(403).json({ message: 'Refresh Token đã hết hạn!' });

      db.get(`SELECT * FROM users WHERE id = ?`, [decoded.id], (err, user) => {
        if (err || !user) return res.status(404).json({ message: 'Tài khoản không tồn tại!' });

        const newToken = jwt.sign(
          { id: user.id, username: user.username, role: user.role, canViewData: user.canViewData },
          JWT_SECRET,
          { expiresIn: '1h' }
        );

        res.json({ token: newToken });
      });
    });
  });
});

app.post('/api/logout', (req, res) => {
  const { refreshToken } = req.body;
  db.run(`DELETE FROM refresh_tokens WHERE token = ?`, [refreshToken], (err) => {
    res.json({ message: 'Đăng xuất thành công!' });
  });
});

// 👑 API dành cho ADMIN: Lấy danh sách user để duyệt quyền
app.get('/api/admin/users', (req, res) => {
  db.all(`SELECT id, username, role, canViewData FROM users`, [], (err, rows) => {
    res.json(rows);
  });
});

// 👑 API dành cho ADMIN: Bật/Tắt quyền xem kho lạnh cho User
app.post('/api/admin/toggle-permission', (req, res) => {
  const { userId, canViewData } = req.body; // canViewData: 1 hoặc 0
  db.run(`UPDATE users SET canViewData = ? WHERE id = ?`, [canViewData, userId], (err) => {
    res.json({ message: 'Đã cập nhật quyền thành công!' });
  });
});

// ==========================================
// 2. NHẬN DỮ LIỆU NHIỆT ĐỘ & BẮN XUỐNG WEB
// ==========================================

// Kết nối tới nơi cảm biến/PLC gửi dữ liệu vào
const mqttClient = mqtt.connect('mqtt://broker.hivemq.com');

mqttClient.on('connect', () => {
  console.log('✅ Đã kết nối kênh nhận dữ liệu cảm biến!');
  mqttClient.subscribe('kholanh/nhietdo'); // Đăng ký nghe kênh này
});

// Khi có nhiệt độ mới gửi đến
mqttClient.on('message', (topic, message) => {
  const dataNhietDo = message.toString();

  // Bắn dữ liệu tới TẤT CẢ các trang web đang kết nối và CÓ QUYỀN XEM
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && client.canViewData) {
      client.send(dataNhietDo);
    }
  });
});

// Kiểm tra quyền khi trang Web mở kết nối WebSocket (Real-time)
wss.on('connection', (ws, req) => {
  // Lấy token từ link dạng: ws://localhost:3000?token=XXX
  const token = new URLSearchParams(req.url.replace('/?', '')).get('token');

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err || (decoded.role !== 'admin' && !decoded.canViewData)) {
      ws.send(JSON.stringify({ error: 'Bạn chưa được Admin cấp quyền xem kho lạnh!' }));
      ws.close();
    } else {
      ws.canViewData = true; // Cho phép nhận dữ liệu
      console.log(`👤 ${decoded.username} đang xem nhiệt độ kho lạnh...`);
    }
  });
});

server.listen(3000, () => console.log('🚀 Server đã chạy tại port 3000'));