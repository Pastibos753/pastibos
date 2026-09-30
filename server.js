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

// Middleware Verifikasi Token User Biasa
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

// Middleware Verifikasi Token Khusus Admin
function verifyAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Akses admin ditolak. Silakan login sebagai admin.' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'pastibos_secret_key_123456789');
    if (decoded.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Hanya akun Admin yang diizinkan mengakses panel ini!' });
    }
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ success: false, message: 'Sesi admin kadaluarsa. Silakan login ulang.' });
  }
}

function generateTrxCode(prefix) {
  return `${prefix}-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`;
}

// ==========================================
// RUTE UMUM & HEALTH CHECK
// ==========================================
app.get('/', (req, res) => {
  res.json({
    status: 'ONLINE',
    message: '🚀 Selamat! Backend Platform Game PASTIBOS sudah aktif dan siap melayani data.',
    database: 'TiDB Cloud Connected',
    time: new Date()
  });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Backend PASTIBOS aktif di Vercel!', timestamp: new Date() });
});

// ==========================================
// RUTE PEMAIN (AUTH & WALLET)
// ==========================================
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
    if (user.status === 'suspended') {
      return res.status(403).json({ success: false, message: 'Akun Anda sedang dibekukan / diblokir oleh Admin.' });
    }

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
          balance: parseFloat(user.balance),
          role: user.role
        }
      }
    });
  } catch (error) {
    console.error('Error Login:', error);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server saat login.' });
  }
});

app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, phone, bank_name, account_name, account_number, balance, role, status, created_at FROM users WHERE id = ? LIMIT 1',
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
        role: u.role,
        status: u.status,
        created_at: u.created_at
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Gagal mengambil data user.' });
  }
});

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

// ==========================================
// 4. ENDPOINT KHUSUS PANEL ADMIN
// ==========================================

// Inisialisasi Akun Admin Pertama Kali (Otomatis & Sekali Jalan)
app.get('/api/admin/setup', async (req, res) => {
  try {
    const [existing] = await pool.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
    if (existing.length > 0) {
      return res.json({ success: true, message: 'Akun Admin sudah siap aktif di database!' });
    }

    const salt = await bcrypt.genSalt(10);
    const defaultPassword = 'adminboss123';
    const hashedPassword = await bcrypt.hash(defaultPassword, salt);

    await pool.execute(
      `INSERT INTO users (username, password_hash, phone, bank_name, account_name, account_number, balance, role) 
       VALUES ('adminbos', ?, '08123456789', 'BCA', 'ADMIN PASTIBOS', '00000000', 9999999.00, 'admin')`,
      [hashedPassword]
    );

    return res.json({
      success: true,
      message: '✅ Berhasil membuat akun Admin pertama!',
      credentials: {
        username: 'adminbos',
        password: defaultPassword
      }
    });
  } catch (error) {
    console.error('Error Admin Setup:', error);
    return res.status(500).json({ success: false, message: 'Gagal membuat akun admin: ' + error.message });
  }
});

// Login Khusus Admin Panel
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username dan password wajib diisi!' });
    }

    const [rows] = await pool.execute("SELECT * FROM users WHERE username = ? AND role = 'admin' LIMIT 1", [username]);
    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Akun Admin tidak ditemukan atau bukan berstatus Admin!' });
    }

    const admin = rows[0];
    const isMatch = await bcrypt.compare(password, admin.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Password admin salah!' });
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, role: 'admin' },
      process.env.JWT_SECRET || 'pastibos_secret_key_123456789',
      { expiresIn: '7d' }
    );

    return res.status(200).json({
      success: true,
      message: 'Login Admin Berhasil!',
      data: { token, username: admin.username }
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Server error saat login admin.' });
  }
});

// Ambil Seluruh Daftar Pemain
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, username, phone, bank_name, account_name, account_number, referral_code, balance, status, role, created_at 
       FROM users WHERE role != 'admin' ORDER BY created_at DESC`
    );
    const formatted = rows.map(u => ({ ...u, balance: parseFloat(u.balance) }));
    return res.json({ success: true, count: formatted.length, data: formatted });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Gagal mengambil data pemain.' });
  }
});

// Kontrol Saldo Pemain (Tambah / Kurangi Saldo oleh Admin)
app.post('/api/admin/users/adjust-balance', verifyAdmin, async (req, res) => {
  const { userId, amount, action, note } = req.body; // action: 'add' atau 'subtract'
  const nominal = parseFloat(amount);

  if (!userId || isNaN(nominal) || nominal <= 0) {
    return res.status(400).json({ success: false, message: 'Data user dan nominal tidak valid!' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [rows] = await conn.execute('SELECT balance, username FROM users WHERE id = ? FOR UPDATE', [userId]);
    if (rows.length === 0) {
      await conn.rollback();
      return res.status(404).json({ success: false, message: 'User tidak ditemukan.' });
    }

    const currentBalance = parseFloat(rows[0].balance);
    let newBalance = currentBalance;
    const trxCode = generateTrxCode(action === 'add' ? 'ADM-PLUS' : 'ADM-MIN');

    if (action === 'add') {
      newBalance = currentBalance + nominal;
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [nominal, userId]);
      await conn.execute(
        `INSERT INTO transactions (user_id, transaction_code, type, amount, status, payment_method, description) 
         VALUES (?, ?, 'TOPUP', ?, 'SUCCESS', 'MANUAL_ADMIN', ?)`,
        [userId, trxCode, nominal, note || 'Penambahan saldo oleh Admin']
      );
    } else if (action === 'subtract') {
      if (currentBalance < nominal) {
        await conn.rollback();
        return res.status(400).json({ success: false, message: `Saldo pemain tidak cukup untuk dipotong! Saldo saat ini: Rp ${currentBalance.toLocaleString('id-ID')}` });
      }
      newBalance = currentBalance - nominal;
      await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [nominal, userId]);
      await conn.execute(
        `INSERT INTO transactions (user_id, transaction_code, type, amount, status, payment_method, description) 
         VALUES (?, ?, 'WITHDRAW', ?, 'SUCCESS', 'MANUAL_ADMIN', ?)`,
        [userId, trxCode, nominal, note || 'Pengurangan saldo oleh Admin']
      );
    }

    await conn.commit();
    return res.json({
      success: true,
      message: `Saldo ${rows[0].username} berhasil diubah! Saldo baru: Rp ${newBalance.toLocaleString('id-ID')}`,
      data: { newBalance }
    });
  } catch (error) {
    await conn.rollback();
    return res.status(500).json({ success: false, message: 'Gagal mengubah saldo: ' + error.message });
  } finally {
    conn.release();
  }
});

// Blokir atau Aktifkan Akun Pemain
app.post('/api/admin/users/toggle-status', verifyAdmin, async (req, res) => {
  const { userId, status } = req.body; // status: 'active' atau 'suspended'
  if (!userId || !['active', 'suspended'].includes(status)) {
    return res.status(400).json({ success: false, message: 'Status tidak valid!' });
  }

  try {
    await pool.execute('UPDATE users SET status = ? WHERE id = ?', [status, userId]);
    return res.json({
      success: true,
      message: `Status akun berhasil diubah menjadi: ${status.toUpperCase()}`
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Gagal mengubah status akun.' });
  }
});

// Ambil Seluruh Riwayat Transaksi Semua Pemain
app.get('/api/admin/transactions', verifyAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT t.id, t.transaction_code, t.type, t.amount, t.status, t.payment_method, t.description, t.created_at, u.username, u.bank_name, u.account_number 
       FROM transactions t 
       JOIN users u ON t.user_id = u.id 
       ORDER BY t.created_at DESC LIMIT 100`
    );
    const formatted = rows.map(t => ({ ...t, amount: parseFloat(t.amount) }));
    return res.json({ success: true, count: formatted.length, data: formatted });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Gagal mengambil riwayat transaksi.' });
  }
});


// Halaman Web Admin Panel Langsung (Bisa dibuka langsung di Browser HP!)
const ADMIN_HTML_CONTENT = `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Admin Control Panel - PASTIBOS</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0a0b0e;
      --bg-card: #12141c;
      --bg-card-hover: #181b26;
      --border: #232838;
      --primary: #f59e0b;
      --primary-hover: #d97706;
      --primary-glow: rgba(245, 158, 11, 0.15);
      --success: #10b981;
      --danger: #ef4444;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: 'Inter', sans-serif;
      -webkit-tap-highlight-color: transparent;
    }

    body {
      background-color: var(--bg-dark);
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* Header */
    header {
      background: #11131a;
      border-bottom: 1px solid var(--border);
      padding: 12px 16px;
      position: sticky;
      top: 0;
      z-index: 100;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .brand-title {
      font-family: 'Rajdhani', sans-serif;
      font-size: 20px;
      font-weight: 700;
      letter-spacing: 1px;
      color: #fff;
    }

    .brand-title span {
      color: var(--primary);
    }

    .badge-admin {
      background: rgba(245, 158, 11, 0.15);
      border: 1px solid var(--primary);
      color: var(--primary);
      font-size: 11px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .btn-logout {
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #f87171;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
    }

    /* Container */
    .container {
      max-width: 1000px;
      width: 100%;
      margin: 0 auto;
      padding: 16px;
      flex: 1;
    }

    /* Login Form Screen */
    #login-view {
      max-width: 400px;
      margin: 40px auto;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
    }

    .login-title {
      font-family: 'Rajdhani', sans-serif;
      font-size: 24px;
      font-weight: 700;
      text-align: center;
      color: #fff;
      margin-bottom: 6px;
    }

    .login-desc {
      text-align: center;
      color: var(--text-muted);
      font-size: 13px;
      margin-bottom: 24px;
    }

    .form-group {
      margin-bottom: 16px;
    }

    label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    input, select {
      width: 100%;
      background: #0d0f15;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 14px;
      color: #fff;
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s;
    }

    input:focus, select:focus {
      border-color: var(--primary);
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      font-weight: 600;
      font-size: 13px;
      padding: 10px 16px;
      border-radius: 8px;
      border: none;
      cursor: pointer;
      transition: all 0.2s;
    }

    .btn-block {
      width: 100%;
    }

    .btn-primary {
      background: var(--primary);
      color: #000;
      font-weight: 700;
    }

    .btn-primary:active {
      transform: scale(0.98);
      background: var(--primary-hover);
    }

    .btn-success {
      background: #059669;
      color: #fff;
    }

    .btn-danger {
      background: #dc2626;
      color: #fff;
    }

    .btn-secondary {
      background: #272b38;
      color: #d1d5db;
    }

    .btn-sm {
      padding: 6px 10px;
      font-size: 12px;
      border-radius: 6px;
    }

    /* Stats Overview */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 12px;
      margin-bottom: 20px;
    }

    @media (min-width: 640px) {
      .stats-grid {
        grid-template-columns: repeat(4, 1fr);
      }
    }

    .stat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
    }

    .stat-label {
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.5px;
      margin-bottom: 4px;
    }

    .stat-value {
      font-family: 'Rajdhani', sans-serif;
      font-size: 22px;
      font-weight: 700;
      color: #fff;
    }

    .stat-value.gold {
      color: var(--primary);
    }

    /* Tab Switcher */
    .tabs {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 10px;
      overflow-x: auto;
    }

    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 14px;
      font-weight: 600;
      padding: 8px 14px;
      border-radius: 6px;
      cursor: pointer;
      white-space: nowrap;
    }

    .tab-btn.active {
      background: var(--primary-glow);
      color: var(--primary);
    }

    /* Filter / Search */
    .search-bar {
      margin-bottom: 16px;
      position: relative;
    }

    /* User Cards on Mobile / Table */
    .player-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 12px;
      position: relative;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .player-card.suspended {
      opacity: 0.7;
      border-color: rgba(239, 68, 68, 0.4);
    }

    .player-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }

    .player-username {
      font-size: 16px;
      font-weight: 700;
      color: #fff;
    }

    .player-phone {
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 2px;
    }

    .badge-status {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      text-transform: uppercase;
    }

    .badge-active {
      background: rgba(16, 185, 129, 0.15);
      color: var(--success);
      border: 1px solid var(--success);
    }

    .badge-suspended {
      background: rgba(239, 68, 68, 0.15);
      color: var(--danger);
      border: 1px solid var(--danger);
    }

    .player-info-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      background: #0d0f15;
      padding: 10px;
      border-radius: 8px;
      font-size: 12px;
    }

    .info-label {
      color: var(--text-muted);
      font-size: 11px;
    }

    .info-val {
      font-weight: 600;
      color: #e5e7eb;
      word-break: break-all;
    }

    .player-balance-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(245, 158, 11, 0.08);
      border: 1px dashed rgba(245, 158, 11, 0.3);
      padding: 10px 14px;
      border-radius: 8px;
    }

    .balance-label {
      font-size: 12px;
      color: var(--text-muted);
    }

    .balance-val {
      font-family: 'Rajdhani', sans-serif;
      font-size: 20px;
      font-weight: 700;
      color: var(--primary);
    }

    .player-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .player-actions .btn {
      flex: 1;
      white-space: nowrap;
    }

    /* Modal */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(4px);
      display: none;
      align-items: center;
      justify-content: center;
      padding: 16px;
      z-index: 200;
    }

    .modal-box {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      width: 100%;
      max-width: 420px;
      padding: 20px;
      position: relative;
    }

    .modal-title {
      font-family: 'Rajdhani', sans-serif;
      font-size: 20px;
      font-weight: 700;
      color: #fff;
      margin-bottom: 6px;
    }

    .modal-subtitle {
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 16px;
    }

    .quick-chips {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 8px;
      margin-bottom: 14px;
    }

    .chip {
      background: #0d0f15;
      border: 1px solid var(--border);
      padding: 8px 4px;
      text-align: center;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      color: #d1d5db;
    }

    .chip:active {
      border-color: var(--primary);
      color: var(--primary);
    }

    .modal-buttons {
      display: flex;
      gap: 10px;
      margin-top: 20px;
    }

    /* Transaction Table */
    .trx-table-wrap {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      text-align: left;
    }

    th, td {
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
    }

    th {
      background: #11131a;
      color: var(--text-muted);
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 600;
    }

    .type-topup {
      color: var(--success);
      font-weight: 600;
    }

    .type-withdraw {
      color: #f87171;
      font-weight: 600;
    }

    /* Toast */
    #toast {
      position: fixed;
      bottom: 20px;
      left: 50%;
      transform: translateX(-50%);
      background: #1f2937;
      color: #fff;
      padding: 12px 20px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 500;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      border: 1px solid #374151;
      display: none;
      z-index: 300;
      max-width: 90%;
      text-align: center;
    }
  </style>
</head>
<body>

  <!-- Header -->
  <header>
    <div class="brand">
      <div class="brand-title">PASTI<span>BOS</span></div>
      <span class="badge-admin">Admin Panel</span>
    </div>
    <div id="header-user" style="display: none; align-items: center; gap: 10px;">
      <span id="admin-name" style="font-size: 12px; color: var(--text-muted); font-weight: 600;"></span>
      <button class="btn-logout" onclick="logoutAdmin()">Keluar</button>
    </div>
  </header>

  <!-- Login Form Screen -->
  <div id="login-view" class="container">
    <h2 class="login-title">LOGIN PENGELOLA</h2>
    <p class="login-desc">Masukkan akun Admin untuk mengelola pemain dan saldo</p>

    <form id="admin-login-form" onsubmit="handleLogin(event)">
      <div class="form-group">
        <label>Username Admin</label>
        <input type="text" id="login-username" placeholder="Contoh: adminbos" required autocomplete="username">
      </div>
      <div class="form-group">
        <label>Password Admin</label>
        <input type="password" id="login-password" placeholder="••••••••" required autocomplete="current-password">
      </div>
      <button type="submit" class="btn btn-primary btn-block" id="btn-login-submit">MASUK KE PANEL ADMIN</button>
    </form>
    
    <div style="margin-top: 20px; text-align: center; font-size: 11px; color: var(--text-muted); border-top: 1px solid var(--border); padding-top: 14px;">
      Belum membuat akun Admin pertama? Klik link ini:<br>
      <a href="https://pastibos.vercel.app/api/admin/setup" target="_blank" style="color: var(--primary); font-weight: 600; text-decoration: none;">
        👉 Inisialisasi Akun Admin Otomatis
      </a>
    </div>
  </div>

  <!-- Dashboard Admin Screen -->
  <div id="dashboard-view" class="container" style="display: none;">
    <!-- Stats Row -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Total Pemain</div>
        <div class="stat-value" id="stat-total-users">0</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Total Saldo Member</div>
        <div class="stat-value gold" id="stat-total-balance">Rp 0</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Akun Aktif</div>
        <div class="stat-value" id="stat-active-users" style="color: var(--success);">0</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Akun Diblokir</div>
        <div class="stat-value" id="stat-suspended-users" style="color: var(--danger);">0</div>
      </div>
    </div>

    <!-- Tabs Navigation -->
    <div class="tabs">
      <button class="tab-btn active" id="tab-btn-users" onclick="switchTab('users')">👥 Daftar Pemain (<span id="user-count-badge">0</span>)</button>
      <button class="tab-btn" id="tab-btn-trx" onclick="switchTab('trx')">📜 Riwayat Transaksi Platform</button>
    </div>

    <!-- Tab 1: Players Section -->
    <div id="section-users">
      <div class="search-bar">
        <input type="text" id="search-input" placeholder="🔍 Cari nama pemain, no telepon, no rekening..." oninput="filterPlayers()">
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <span style="font-size: 13px; color: var(--text-muted);">Daftar Akun Terdaftar:</span>
        <button class="btn btn-secondary btn-sm" onclick="loadPlayers()">🔄 Segarkan Data</button>
      </div>

      <!-- Player Cards Container -->
      <div id="players-list">
        <div style="text-align: center; padding: 40px; color: var(--text-muted);">Memuat data pemain...</div>
      </div>
    </div>

    <!-- Tab 2: Transactions Section -->
    <div id="section-trx" style="display: none;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <span style="font-size: 13px; color: var(--text-muted);">100 Transaksi Terakhir (Semua Member):</span>
        <button class="btn btn-secondary btn-sm" onclick="loadTransactions()">🔄 Segarkan Transaksi</button>
      </div>

      <div class="trx-table-wrap">
        <table>
          <thead>
            <tr>
              <th>Waktu</th>
              <th>Pemain</th>
              <th>Kode Trx</th>
              <th>Tipe</th>
              <th>Nominal</th>
              <th>Metode</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody id="trx-list-tbody">
            <tr>
              <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 20px;">Memuat transaksi...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Modal: Adjust Balance (+ / - Saldo) -->
  <div class="modal-overlay" id="balance-modal">
    <div class="modal-box">
      <h3 class="modal-title" id="modal-user-title">Atur Saldo</h3>
      <p class="modal-subtitle" id="modal-user-sub">Pemain: -</p>

      <div class="form-group">
        <label>Pilih Tindakan</label>
        <select id="modal-action-type">
          <option value="add">➕ TAMBAH SALDO (Deposit Manual)</option>
          <option value="subtract">➖ KURANGI SALDO (Tarik Saldo Manual)</option>
        </select>
      </div>

      <div class="form-group">
        <label>Nominal Cepat</label>
        <div class="quick-chips">
          <div class="chip" onclick="setQuickAmount(10000)">10 Ribu</div>
          <div class="chip" onclick="setQuickAmount(50000)">50 Ribu</div>
          <div class="chip" onclick="setQuickAmount(100000)">100 Ribu</div>
          <div class="chip" onclick="setQuickAmount(250000)">250 Ribu</div>
          <div class="chip" onclick="setQuickAmount(500000)">500 Ribu</div>
          <div class="chip" onclick="setQuickAmount(1000000)">1 Juta</div>
        </div>
      </div>

      <div class="form-group">
        <label>Nominal Rupiah (Rp)</label>
        <input type="number" id="modal-amount" placeholder="Contoh: 100000" min="1000" step="1000" required>
      </div>

      <div class="form-group">
        <label>Keterangan / Catatan (Opsional)</label>
        <input type="text" id="modal-note" placeholder="Contoh: Bonus New Member / Topup via WA">
      </div>

      <div class="modal-buttons">
        <button type="button" class="btn btn-secondary" style="flex: 1;" onclick="closeBalanceModal()">Batal</button>
        <button type="button" class="btn btn-primary" style="flex: 1;" id="btn-modal-confirm" onclick="submitBalanceAdjust()">Simpan Perubahan</button>
      </div>
    </div>
  </div>

  <!-- Toast Notification -->
  <div id="toast"></div>

  <script>
    // Konfigurasi API Backend Vercel
    const API_BASE = 'https://pastibos.vercel.app/api';

    let allPlayers = [];
    let currentTargetUserId = null;
    let currentTargetUsername = '';

    // Inisialisasi saat halaman dibuka
    document.addEventListener('DOMContentLoaded', () => {
      checkAuth();
    });

    function checkAuth() {
      const token = localStorage.getItem('pastibos_admin_token');
      const adminName = localStorage.getItem('pastibos_admin_username');

      if (token) {
        document.getElementById('login-view').style.display = 'none';
        document.getElementById('dashboard-view').style.display = 'block';
        document.getElementById('header-user').style.display = 'flex';
        document.getElementById('admin-name').textContent = 'Admin: ' + (adminName || 'Admin');
        loadPlayers();
      } else {
        document.getElementById('login-view').style.display = 'block';
        document.getElementById('dashboard-view').style.display = 'none';
        document.getElementById('header-user').style.display = 'none';
      }
    }

    async function handleLogin(e) {
      e.preventDefault();
      const usernameInput = document.getElementById('login-username').value.trim();
      const passwordInput = document.getElementById('login-password').value.trim();
      const btn = document.getElementById('btn-login-submit');

      if (!usernameInput || !passwordInput) {
        showToast('Username dan password wajib diisi!');
        return;
      }

      btn.disabled = true;
      btn.textContent = 'Memverifikasi...';

      try {
        const res = await fetch(\`\${API_BASE}/admin/login\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: usernameInput, password: passwordInput })
        });
        const data = await res.json();

        if (data.success && data.data && data.data.token) {
          localStorage.setItem('pastibos_admin_token', data.data.token);
          localStorage.setItem('pastibos_admin_username', data.data.username);
          showToast('✅ Berhasil login sebagai Admin!');
          checkAuth();
        } else {
          showToast(data.message || 'Gagal login. Periksa username dan password!');
        }
      } catch (err) {
        showToast('Gagal menghubungi server. Pastikan Vercel aktif!');
      } finally {
        btn.disabled = false;
        btn.textContent = 'MASUK KE PANEL ADMIN';
      }
    }

    function logoutAdmin() {
      if (confirm('Keluar dari Panel Admin?')) {
        localStorage.removeItem('pastibos_admin_token');
        localStorage.removeItem('pastibos_admin_username');
        checkAuth();
      }
    }

    // Ambil Daftar Pemain dari Server
    async function loadPlayers() {
      const token = localStorage.getItem('pastibos_admin_token');
      const container = document.getElementById('players-list');
      container.innerHTML = '<div style="text-align: center; padding: 30px; color: var(--text-muted);">Memuat data pemain...</div>';

      try {
        const res = await fetch(\`\${API_BASE}/admin/users\`, {
          headers: { 'Authorization': \`Bearer \${token}\` }
        });
        
        if (res.status === 401 || res.status === 403) {
          showToast('Sesi login telah habis, silakan login ulang.');
          logoutAdmin();
          return;
        }

        const data = await res.json();
        if (data.success) {
          allPlayers = data.data || [];
          renderStats(allPlayers);
          renderPlayers(allPlayers);
        } else {
          container.innerHTML = \`<div style="text-align: center; padding: 20px; color: #f87171;">\${data.message}</div>\`;
        }
      } catch (err) {
        container.innerHTML = '<div style="text-align: center; padding: 20px; color: #f87171;">Gagal mengambil data dari server.</div>';
      }
    }

    function renderStats(players) {
      document.getElementById('stat-total-users').textContent = players.length;
      document.getElementById('user-count-badge').textContent = players.length;

      const totalBalance = players.reduce((sum, p) => sum + (parseFloat(p.balance) || 0), 0);
      document.getElementById('stat-total-balance').textContent = 'Rp ' + totalBalance.toLocaleString('id-ID');

      const activeCount = players.filter(p => p.status === 'active').length;
      const suspendedCount = players.filter(p => p.status === 'suspended').length;
      document.getElementById('stat-active-users').textContent = activeCount;
      document.getElementById('stat-suspended-users').textContent = suspendedCount;
    }

    function renderPlayers(players) {
      const container = document.getElementById('players-list');
      if (players.length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 30px; color: var(--text-muted);">Belum ada pemain yang terdaftar.</div>';
        return;
      }

      container.innerHTML = players.map(p => {
        const isSuspended = p.status === 'suspended';
        return \`
          <div class="player-card \${isSuspended ? 'suspended' : ''}">
            <div class="player-header">
              <div>
                <div class="player-username">👤 \${escapeHtml(p.username)}</div>
                <div class="player-phone">📱 \${escapeHtml(p.phone || '-')} | Ref: \${escapeHtml(p.referral_code || '-')}</div>
              </div>
              <span class="badge-status \${isSuspended ? 'badge-suspended' : 'badge-active'}">
                \${isSuspended ? 'DIBLOKIR' : 'AKTIF'}
              </span>
            </div>

            <div class="player-info-grid">
              <div>
                <div class="info-label">Bank / E-Wallet</div>
                <div class="info-val">\${escapeHtml(p.bank_name || '-')}</div>
              </div>
              <div>
                <div class="info-label">Nomor Rekening</div>
                <div class="info-val">\${escapeHtml(p.account_number || '-')}</div>
              </div>
              <div>
                <div class="info-label">Nama Pemilik</div>
                <div class="info-val">\${escapeHtml(p.account_name || '-')}</div>
              </div>
              <div>
                <div class="info-label">Tanggal Daftar</div>
                <div class="info-val">\${formatDate(p.created_at)}</div>
              </div>
            </div>

            <div class="player-balance-row">
              <span class="balance-label">SALDO AKUN:</span>
              <span class="balance-val">Rp \${(parseFloat(p.balance) || 0).toLocaleString('id-ID')}</span>
            </div>

            <div class="player-actions">
              <button class="btn btn-success btn-sm" onclick="openBalanceModal(\${p.id}, '\${escapeHtml(p.username)}', 'add')">
                ➕ Tambah Saldo
              </button>
              <button class="btn btn-danger btn-sm" onclick="openBalanceModal(\${p.id}, '\${escapeHtml(p.username)}', 'subtract')">
                ➖ Kurangi Saldo
              </button>
              <button class="btn btn-secondary btn-sm" onclick="togglePlayerStatus(\${p.id}, '\${p.status}')">
                \${isSuspended ? '🔓 Buka Blokir' : '🔒 Blokir'}
              </button>
            </div>
          </div>
        \`;
      }).join('');
    }

    function filterPlayers() {
      const keyword = document.getElementById('search-input').value.toLowerCase().trim();
      if (!keyword) {
        renderPlayers(allPlayers);
        return;
      }
      const filtered = allPlayers.filter(p => 
        (p.username && p.username.toLowerCase().includes(keyword)) ||
        (p.phone && p.phone.toLowerCase().includes(keyword)) ||
        (p.bank_name && p.bank_name.toLowerCase().includes(keyword)) ||
        (p.account_number && p.account_number.toLowerCase().includes(keyword)) ||
        (p.account_name && p.account_name.toLowerCase().includes(keyword))
      );
      renderPlayers(filtered);
    }

    // Modal Atur Saldo
    function openBalanceModal(userId, username, action) {
      currentTargetUserId = userId;
      currentTargetUsername = username;
      document.getElementById('modal-user-title').textContent = action === 'add' ? '➕ Tambah Saldo Member' : '➖ Kurangi Saldo Member';
      document.getElementById('modal-user-sub').textContent = \`Target Akun: \${username}\`;
      document.getElementById('modal-action-type').value = action;
      document.getElementById('modal-amount').value = '';
      document.getElementById('modal-note').value = '';
      document.getElementById('balance-modal').style.display = 'flex';
    }

    function closeBalanceModal() {
      document.getElementById('balance-modal').style.display = 'none';
      currentTargetUserId = null;
      currentTargetUsername = '';
    }

    function setQuickAmount(amount) {
      document.getElementById('modal-amount').value = amount;
    }

    async function submitBalanceAdjust() {
      const token = localStorage.getItem('pastibos_admin_token');
      const action = document.getElementById('modal-action-type').value;
      const amount = parseFloat(document.getElementById('modal-amount').value);
      const note = document.getElementById('modal-note').value.trim();
      const btn = document.getElementById('btn-modal-confirm');

      if (!amount || isNaN(amount) || amount <= 0) {
        showToast('Masukkan nominal rupiah yang valid!');
        return;
      }

      btn.disabled = true;
      btn.textContent = 'Memproses...';

      try {
        const res = await fetch(\`\${API_BASE}/admin/users/adjust-balance\`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': \`Bearer \${token}\`
          },
          body: JSON.stringify({
            userId: currentTargetUserId,
            amount: amount,
            action: action,
            note: note || (action === 'add' ? 'Deposit manual admin' : 'Penarikan manual admin')
          })
        });

        const data = await res.json();
        if (data.success) {
          showToast(\`✅ \${data.message}\`);
          closeBalanceModal();
          loadPlayers(); // Refresh list & saldo
        } else {
          showToast(\`❌ \${data.message}\`);
        }
      } catch (err) {
        showToast('Gagal memproses saldo ke server.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Simpan Perubahan';
      }
    }

    // Toggle Status Blokir
    async function togglePlayerStatus(userId, currentStatus) {
      const nextStatus = currentStatus === 'active' ? 'suspended' : 'active';
      const promptText = nextStatus === 'suspended' ? 'Yakin ingin MEMBLOKIR akun ini?' : 'Yakin ingin MEMBUKA BLOKIR akun ini?';

      if (!confirm(promptText)) return;

      const token = localStorage.getItem('pastibos_admin_token');
      try {
        const res = await fetch(\`\${API_BASE}/admin/users/toggle-status\`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': \`Bearer \${token}\`
          },
          body: JSON.stringify({ userId: userId, status: nextStatus })
        });
        const data = await res.json();
        if (data.success) {
          showToast(\`✅ Status akun berhasil diubah ke \${nextStatus.toUpperCase()}\`);
          loadPlayers();
        } else {
          showToast(\`❌ \${data.message}\`);
        }
      } catch (err) {
        showToast('Gagal menghubungi server.');
      }
    }

    // Riwayat Transaksi Platform
    async function loadTransactions() {
      const token = localStorage.getItem('pastibos_admin_token');
      const tbody = document.getElementById('trx-list-tbody');
      tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 20px;">Memuat transaksi...</td></tr>';

      try {
        const res = await fetch(\`\${API_BASE}/admin/transactions\`, {
          headers: { 'Authorization': \`Bearer \${token}\` }
        });
        const data = await res.json();

        if (data.success && data.data) {
          if (data.data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 20px;">Belum ada transaksi di platform.</td></tr>';
            return;
          }

          tbody.innerHTML = data.data.map(t => {
            const isTopup = t.type === 'TOPUP';
            return \`
              <tr>
                <td style="font-size: 11px; color: var(--text-muted);">\${formatDate(t.created_at)}</td>
                <td><strong>\${escapeHtml(t.username)}</strong><br><small style="color: var(--text-muted);">\${escapeHtml(t.bank_name || '')}</small></td>
                <td style="font-size: 11px;">\${escapeHtml(t.transaction_code)}</td>
                <td><span class="\${isTopup ? 'type-topup' : 'type-withdraw'}">\${isTopup ? '+ TOPUP' : '- WD'}</span></td>
                <td><strong>Rp \${(parseFloat(t.amount) || 0).toLocaleString('id-ID')}</strong></td>
                <td style="font-size: 11px;">\${escapeHtml(t.payment_method)}</td>
                <td><span style="font-size: 10px; font-weight: 700; color: \${t.status === 'SUCCESS' ? 'var(--success)' : '#f59e0b'};">\${t.status}</span></td>
              </tr>
            \`;
          }).join('');
        } else {
          tbody.innerHTML = \`<tr><td colspan="7" style="text-align: center; color: #f87171; padding: 20px;">\${data.message}</td></tr>\`;
        }
      } catch (err) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #f87171; padding: 20px;">Gagal memuat transaksi.</td></tr>';
      }
    }

    // Switch Tabs
    function switchTab(tab) {
      const btnUsers = document.getElementById('tab-btn-users');
      const btnTrx = document.getElementById('tab-btn-trx');
      const secUsers = document.getElementById('section-users');
      const secTrx = document.getElementById('section-trx');

      if (tab === 'users') {
        btnUsers.classList.add('active');
        btnTrx.classList.remove('active');
        secUsers.style.display = 'block';
        secTrx.style.display = 'none';
      } else {
        btnTrx.classList.add('active');
        btnUsers.classList.remove('active');
        secUsers.style.display = 'none';
        secTrx.style.display = 'block';
        loadTransactions();
      }
    }

    // Utils
    function showToast(msg) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.style.display = 'block';
      setTimeout(() => {
        toast.style.display = 'none';
      }, 3500);
    }

    function formatDate(dateStr) {
      if (!dateStr) return '-';
      const d = new Date(dateStr);
      return d.toLocaleDateString('id-ID', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/[&<>"']/g, function(m) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
      });
    }
  </script>
</body>
</html>
`;

app.get('/api/admin-panel', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(ADMIN_HTML_CONTENT);
});

app.get('/admin', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(ADMIN_HTML_CONTENT);
});

module.exports = app;

if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`Server berjalan di port ${PORT}`));
}
