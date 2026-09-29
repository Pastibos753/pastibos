const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 1. KONEKSI DATABASE MYSQL (TIDB CLOUD SSL)
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'game_platform',
  port: parseInt(process.env.DB_PORT || '4000', 10),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: process.env.DB_HOST && process.env.DB_HOST.includes('tidbcloud.com') ? {
    minVersion: 'TLSv1.2',
    rejectUnauthorized: true
  } : undefined
});

// Middleware Verifikasi Token
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Akses ditolak. Token tidak ditemukan.' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'pastibos_secret_key_123456789');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ success: false, message: 'Sesi tidak valid atau sudah kadaluarsa.' });
  }
}

function generateTrxCode(prefix) {
  return `${prefix}-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`;
}

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ONLINE',
    message: '🚀 Selamat! Backend Platform Game PASTIBOS sudah aktif dan siap melayani data.',
    database: 'TiDB Cloud Connected',
    time: new Date() });
});

// REGISTER PENGGUNA
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, phone, bank, namaRek, noRek, referral } = req.body;

    if (!username || !password || !phone || !bank || !namaRek || !noRek) {
      return res.status(400).json({ success: false, message: 'Semua kolom wajib diisi dengan lengkap!' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password minimal 6 karakter!' });
    }

    const [existing] = await pool.execute('SELECT id FROM users WHERE username = ? LIMIT 1', [username]);
    if (existing.length > 0) {
      return res.status(409).json({ success: false, message: 'Username sudah terdaftar! Gunakan yang lain.' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const [result] = await pool.execute(
      `INSERT INTO users (username, password_hash, phone, bank_name, account_name, account_number, referral_code, balance, role) 
       VALUES (?, ?, ?, ?, ?, ?, ?, 0.00, 'user')`,
      [username, hashedPassword, phone, bank.toUpperCase(), namaRek, noRek, referral || null]
    );

    const newUserId = result.insertId;
    const token = jwt.sign(
      { id: newUserId, username, role: 'user' },
      process.env.JWT_SECRET || 'pastibos_secret_key_123456789',
      { expiresIn: '7d' }
    );

    return res.status(201).json({
      success: true,
      message: 'Pendaftaran akun berhasil!',
      data: {
        token,
        user: { id: newUserId, username, phone, bank: bank.toUpperCase(), namaRek, noRek, balance: 0.00 }
      }
    });
  } catch (error) {
    console.error('Error Register:', error);
    return res.status(500).json({ success: false, message: 'Gagal memproses registrasi di database.' });
  }
});

// LOGIN PENGGUNA
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username dan kata sandi wajib diisi!' });
    }

    const [rows] = await pool.execute('SELECT * FROM users WHERE username = ? LIMIT 1', [username]);
    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Akun tidak ditemukan. Periksa kembali username Anda.' });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Kata sandi salah. Silakan coba lagi.' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'pastibos_secret_key_123456789',
      { expiresIn: '7d' }
    );

    return res.status(200).json({
      success: true,
      message: 'Login berhasil!',
      data: {
        token,
        user: {
          id: user.id,
          username: user.username,
          phone: user.phone,
          bank: user.bank_name,
          namaRek: user.account_name,
          noRek: user.account_number,
          balance: parseFloat(user.balance)
        }
      }
    });
  } catch (error) {
    console.error('Error Login:', error);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server saat login.' });
  }
});

// PROFIL USER (ME)
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, phone, bank_name, account_name, account_number, balance, role, created_at FROM users WHERE id = ? LIMIT 1',
      [req.user.id]
    );
    if (rows.length === 0) return res.status(404).json({ success: false, message: 'User tidak ditemukan.' });

    const u = rows[0];
    return res.status(200).json({
      success: true,
      data: {
        id: u.id,
        username: u.username,
        phone: u.phone,
        bank: u.bank_name,
        namaRek: u.account_name,
        noRek: u.account_number,
        balance: parseFloat(u.balance),
        created_at: u.created_at
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Gagal mengambil data user.' });
  }
});

// TOPUP SALDO
app.post('/api/wallet/topup', verifyToken, async (req, res) => {
  const userId = req.user.id;
  const amount = parseFloat(req.body.amount);
  const paymentMethod = req.body.payment_method || 'QRIS';

  if (isNaN(amount) || amount < 50000) {
    return res.status(400).json({ success: false, message: 'Nominal deposit minimal adalah Rp 50.000!' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const trxCode = generateTrxCode('TOP');

    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, userId]);
    await conn.execute(
      `INSERT INTO transactions (user_id, transaction_code, type, amount, status, payment_method, description) 
       VALUES (?, ?, 'TOPUP', ?, 'SUCCESS', ?, ?)`,
      [userId, trxCode, amount, paymentMethod, `Deposit Saldo via ${paymentMethod}`]
    );

    const [userRows] = await conn.execute('SELECT balance FROM users WHERE id = ?', [userId]);
    await conn.commit();

    return res.status(200).json({
      success: true,
      message: `Deposit sebesar Rp ${amount.toLocaleString('id-ID')} berhasil diproses!`,
      data: { transaction_code: trxCode, amount, new_balance: parseFloat(userRows[0].balance) }
    });
  } catch (err) {
    await conn.rollback();
    return res.status(500).json({ success: false, message: 'Gagal memproses deposit.' });
  } finally {
    conn.release();
  }
});

// PENARIKAN SALDO (WITHDRAW)
app.post('/api/wallet/withdraw', verifyToken, async (req, res) => {
  const userId = req.user.id;
  const amount = parseFloat(req.body.amount);
  const destination = req.body.destination || 'Rekening Terdaftar';

  if (isNaN(amount) || amount < 50000) {
    return res.status(400).json({ success: false, message: 'Nominal penarikan minimal adalah Rp 50.000!' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [rows] = await conn.execute('SELECT balance FROM users WHERE id = ? FOR UPDATE', [userId]);
    if (rows.length === 0) {
      await conn.rollback();
      return res.status(404).json({ success: false, message: 'User tidak ditemukan.' });
    }

    const currentBalance = parseFloat(rows[0].balance);
    if (currentBalance < amount) {
      await conn.rollback();
      return res.status(400).json({ success: false, message: 'Saldo tidak mencukupi untuk penarikan ini!' });
    }

    const trxCode = generateTrxCode('WDR');
    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, userId]);
    await conn.execute(
      `INSERT INTO transactions (user_id, transaction_code, type, amount, status, payment_method, description) 
       VALUES (?, ?, 'WITHDRAW', ?, 'SUCCESS', 'BANK_TRANSFER', ?)`,
      [userId, trxCode, amount, `Penarikan saldo ke: ${destination}`]
    );

    const newBalance = currentBalance - amount;
    await conn.commit();

    return res.status(200).json({
      success: true,
      message: `Penarikan sebesar Rp ${amount.toLocaleString('id-ID')} berhasil diproses!`,
      data: { transaction_code: trxCode, amount, new_balance: newBalance }
    });
  } catch (err) {
    await conn.rollback();
    return res.status(500).json({ success: false, message: 'Gagal memproses penarikan saldo.' });
  } finally {
    conn.release();
  }
});

// RIWAYAT TRANSAKSI
app.get('/api/wallet/transactions', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, transaction_code, type, amount, status, payment_method, description, created_at 
       FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );

    const formatted = rows.map(t => ({ ...t, amount: parseFloat(t.amount) }));
    return res.status(200).json({ success: true, count: formatted.length, data: formatted });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Gagal mengambil riwayat transaksi.' });
  }
});

module.exports = app;

if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Server aktif di port ${PORT}`);
  });
      }
