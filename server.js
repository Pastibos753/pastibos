const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'pastibos_secret_key_123456789';

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'game_platform',
  port: parseInt(process.env.DB_PORT || '4000', 10),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: process.env.DB_HOST && process.env.DB_HOST.includes('tidbcloud.com')
    ? { minVersion: 'TLSv1.2', rejectUnauthorized: true }
    : undefined
});

function generateTrxCode(prefix) {
  return `${prefix}-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`;
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    phone: user.phone || '',
    bank_name: user.bank_name || '',
    account_name: user.account_name || '',
    account_number: user.account_number || '',
    referral_code: user.referral_code || '',
    balance: parseFloat(user.balance || 0),
    status: user.status || 'active',
    role: user.role || 'member',
    created_at: user.created_at || null,

    // Alias lama agar halaman lama tetap kompatibel.
    bank: user.bank_name || '',
    namaRek: user.account_name || '',
    noRek: user.account_number || ''
  };
}

function signUserToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role || 'member' },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Akses ditolak. Token tidak ditemukan.' });
  }

  try {
    req.user = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    next();
  } catch (err) {
    return res.status(403).json({ success: false, message: 'Sesi tidak valid atau sudah kadaluarsa.' });
  }
}

function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Akses admin ditolak. Silakan login sebagai admin.' });
  }

  try {
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Hanya akun Admin yang diizinkan mengakses panel ini!' });
    }
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ success: false, message: 'Sesi admin kadaluarsa. Silakan login ulang.' });
  }
}

// =========================================================
// HEALTH CHECK
// =========================================================
app.get('/', (req, res) => {
  res.json({
    status: 'ONLINE',
    message: 'Backend Platform Game PASTIBOS aktif.',
    database: 'TiDB Cloud / MySQL',
    time: new Date()
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Backend PASTIBOS aktif di Vercel!',
    timestamp: new Date()
  });
});

// =========================================================
// MEMBER AUTH - REGISTER
// =========================================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      username,
      password,
      phone,
      bank,
      namaRek,
      noRek,
      referral
    } = req.body || {};

    const cleanUsername = String(username || '').trim();
    const cleanPhone = String(phone || '').trim();
    const cleanBank = String(bank || '').trim();
    const cleanNamaRek = String(namaRek || '').trim();
    const cleanNoRek = String(noRek || '').trim();
    const cleanReferral = String(referral || '').trim();

    if (!cleanUsername || !password || !cleanPhone || !cleanBank || !cleanNamaRek || !cleanNoRek) {
      return res.status(400).json({
        success: false,
        message: 'Semua data wajib diisi kecuali kode referral.'
      });
    }

    if (String(password).length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password minimal 6 karakter.'
      });
    }

    const [existing] = await pool.execute(
      'SELECT id FROM users WHERE username = ? LIMIT 1',
      [cleanUsername]
    );

    if (existing.length > 0) {
      return res.status(409).json({ success: false, message: 'Username sudah terdaftar.' });
    }

    const passwordHash = await bcrypt.hash(String(password), 12);

    // role = member mengikuti struktur database PASTIBOS yang sudah berhasil dipakai saat register.
    const [result] = await pool.execute(
      `INSERT INTO users
       (username, password_hash, phone, bank_name, account_name, account_number,
        referral_code, balance, status, role)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'active', 'user')`,
      [
        cleanUsername,
        passwordHash,
        cleanPhone,
        cleanBank,
        cleanNamaRek,
        cleanNoRek,
        cleanReferral || null
      ]
    );

    const [rows] = await pool.execute(
      `SELECT id, username, phone, bank_name, account_name, account_number,
              referral_code, balance, status, role, created_at
       FROM users WHERE id = ? LIMIT 1`,
      [result.insertId]
    );

    const user = rows[0];
    const token = signUserToken(user);

    return res.status(201).json({
      success: true,
      message: 'Pendaftaran berhasil! Akun Anda sudah dibuat.',
      data: {
        token,
        user: publicUser(user)
      }
    });
  } catch (error) {
    console.error('Member Register Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Pendaftaran gagal karena terjadi kesalahan server/database.'
    });
  }
});

// =========================================================
// MEMBER AUTH - LOGIN
// =========================================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username dan password wajib diisi.' });
    }

    const [rows] = await pool.execute(
      `SELECT id, username, password_hash, phone, bank_name, account_name,
              account_number, referral_code, balance, status, role, created_at
       FROM users WHERE username = ? LIMIT 1`,
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Username atau password salah.' });
    }

    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Username atau password salah.' });
    }

    if (user.role === 'admin') {
      return res.status(403).json({ success: false, message: 'Gunakan halaman login Admin untuk akun Admin.' });
    }

    if (user.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Akun Anda sedang dinonaktifkan.' });
    }

    const token = signUserToken(user);

    return res.json({
      success: true,
      message: 'Login berhasil.',
      data: { token, user: publicUser(user) }
    });
  } catch (error) {
    console.error('Member Login Error:', error);
    return res.status(500).json({ success: false, message: 'Server error saat login member.' });
  }
});

// =========================================================
// MEMBER - DATA AKUN TERKINI
// =========================================================
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, username, phone, bank_name, account_name, account_number,
              referral_code, balance, status, role, created_at
       FROM users WHERE id = ? LIMIT 1`,
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Akun tidak ditemukan.' });
    }

    const user = rows[0];
    if (user.role === 'admin') {
      return res.status(403).json({ success: false, message: 'Endpoint ini untuk member.' });
    }

    if (user.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Akun Anda sedang dinonaktifkan.' });
    }

    return res.json({ success: true, data: publicUser(user) });
  } catch (error) {
    console.error('Auth Me Error:', error);
    return res.status(500).json({ success: false, message: 'Gagal mengambil data akun.' });
  }
});

// =========================================================
// MEMBER - DEPOSIT / TOPUP PENDING
// =========================================================
app.post('/api/wallet/topup', verifyToken, async (req, res) => {
  try {
    const amount = Number(req.body?.amount);
    const paymentMethod = String(req.body?.payment_method || 'QRIS').trim().toUpperCase();

    if (!Number.isFinite(amount) || amount < 50000) {
      return res.status(400).json({ success: false, message: 'Minimal deposit adalah Rp 50.000.' });
    }

    const roundedAmount = Math.floor(amount);
    const allowedMethods = ['QRIS', 'SEABANK', 'BCA', 'BNI', 'BRI', 'CIMB', 'C.I.M.B', 'OVO', 'DANA', 'GOPAY', 'GO-PAY', 'LINKAJA', 'DANAMON', 'BSI'];
    const method = allowedMethods.includes(paymentMethod) ? paymentMethod : 'QRIS';

    const [users] = await pool.execute(
      `SELECT id, username, balance, status, role FROM users WHERE id = ? LIMIT 1`,
      [req.user.id]
    );

    if (users.length === 0 || users[0].role === 'admin') {
      return res.status(404).json({ success: false, message: 'Member tidak ditemukan.' });
    }

    if (users[0].status !== 'active') {
      return res.status(403).json({ success: false, message: 'Akun Anda sedang dinonaktifkan.' });
    }

    const trxCode = generateTrxCode('DEP');

    await pool.execute(
      `INSERT INTO transactions
       (user_id, transaction_code, type, amount, status, payment_method, description)
       VALUES (?, ?, 'TOPUP', ?, 'PENDING', ?, ?)` ,
      [
        req.user.id,
        trxCode,
        roundedAmount,
        method,
        `Permintaan deposit ${method}`
      ]
    );

    // Penting: saldo TIDAK ditambah pada tahap ini.
    const currentBalance = parseFloat(users[0].balance || 0);

    return res.status(201).json({
      success: true,
      message: 'Deposit berhasil dibuat dan menunggu persetujuan Admin.',
      data: {
        transaction_code: trxCode,
        type: 'TOPUP',
        amount: roundedAmount,
        status: 'PENDING',
        new_balance: currentBalance
      }
    });
  } catch (error) {
    console.error('Wallet Topup Error:', error);
    return res.status(500).json({ success: false, message: 'Gagal membuat transaksi deposit.' });
  }
});

// ===============================================
// WITHDRAW MEMBER
// Saldo langsung dipotong saat pengajuan
// Jika REJECT -> saldo dikembalikan
// Jika APPROVE -> saldo tetap berkurang
// ===============================================
app.post('/api/wallet/withdraw', verifyToken, async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const { amount } = req.body;

    const withdrawAmount = Math.round(Number(amount));

    if (!Number.isFinite(withdrawAmount) || withdrawAmount <= 0) {
      return res.status(400).json({
        message: 'Jumlah withdraw tidak valid'
      });
    }

    if (withdrawAmount < 50000) {
      return res.status(400).json({
        message: 'Minimal withdraw Rp50.000'
      });
    }

    await conn.beginTransaction();

    // Kunci data user agar saldo aman dari transaksi bersamaan
    const [users] = await conn.query(
      `SELECT id, balance, status, role
       FROM users
       WHERE id = ?
       FOR UPDATE`,
      [req.user.id]
    );

    if (users.length === 0) {
      await conn.rollback();

      return res.status(404).json({
        message: 'User tidak ditemukan'
      });
    }

    const user = users[0];

    if (user.status !== 'active') {
      await conn.rollback();

      return res.status(403).json({
        message: 'Akun tidak aktif'
      });
    }

    const currentBalance = Number(user.balance || 0);

    if (currentBalance < withdrawAmount) {
      await conn.rollback();

      return res.status(400).json({
        message: 'Saldo tidak mencukupi'
      });
    }

    // ==========================================
    // SALDO LANGSUNG DIKURANGI
    // ==========================================
    const newBalance = currentBalance - withdrawAmount;

    await conn.query(
      `UPDATE users
       SET balance = ?
       WHERE id = ?`,
      [newBalance, req.user.id]
    );

    // ==========================================
    // BUAT TRANSAKSI PENDING
    // ==========================================
    const transactionCode =
      'WD' +
      Date.now() +
      Math.floor(Math.random() * 1000);

    await conn.query(
      `INSERT INTO transactions
       (
         user_id,
         transaction_code,
         type,
         amount,
         status,
         payment_method,
         description
       )
       VALUES (?, ?, 'WITHDRAW', ?, 'PENDING', 'BANK_TRANSFER', ?)`,
      [
        req.user.id,
        transactionCode,
        withdrawAmount,
        'Permintaan penarikan saldo'
      ]
    );

    await conn.commit();

    return res.json({
      success: true,
      message: 'Permintaan withdraw berhasil dibuat dan saldo telah dikurangi',
      amount: withdrawAmount,
      new_balance: newBalance,
      transaction_code: transactionCode
    });

  } catch (error) {
    await conn.rollback();

    console.error('WITHDRAW ERROR:', error);

    return res.status(500).json({
      message: 'Terjadi kesalahan saat withdraw'
    });

  } finally {
    conn.release();
  }
});

// ==============================================
// MEMBER - RIWAYAT TRANSAKSI
// =============================================
app.get('/api/wallet/transactions', verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, transaction_code, type, amount, status, payment_method,
              description, created_at
       FROM transactions
       WHERE user_id = ?
         AND type IN ('TOPUP', 'WITHDRAW')
       ORDER BY created_at DESC, id DESC
       LIMIT 200`,
      [req.user.id]
    );

    const data = rows.map(row => ({
      ...row,
      amount: parseFloat(row.amount || 0)
    }));

    return res.json({ success: true, count: data.length, data });
  } catch (error) {
    console.error('Member Transactions Error:', error);
    return res.status(500).json({ success: false, message: 'Gagal mengambil riwayat transaksi.' });
  }
});

// ===============================================
// ADMIN LOGIN
// =============================================
app.post('/api/admin/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username dan password wajib diisi!' });
    }

    const [rows] = await pool.execute(
      `SELECT * FROM users WHERE username = ? AND role = 'admin' LIMIT 1`,
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Akun Admin tidak ditemukan atau bukan Admin.' });
    }

    const admin = rows[0];

    if (admin.status && admin.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Akun Admin sedang dinonaktifkan.' });
    }

    const validPassword = await bcrypt.compare(password, admin.password_hash);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Password admin salah!' });
    }

    const token = signUserToken(admin);

    return res.json({
      success: true,
      message: 'Login Admin Berhasil!',
      data: { token, username: admin.username }
    });
  } catch (error) {
    console.error('Admin Login Error:', error);
    return res.status(500).json({ success: false, message: 'Server error saat login admin.' });
  }
});

// ===============================================
// ADMIN - USERS
// ============================================
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, username, phone, bank_name, account_name, account_number,
              referral_code, balance, status, role, created_at
       FROM users
       WHERE role != 'admin'
       ORDER BY created_at DESC`
    );

    return res.json({
      success: true,
      count: rows.length,
      data: rows.map(u => ({ ...u, balance: parseFloat(u.balance || 0) }))
    });
  } catch (error) {
    console.error('Get Users Error:', error);
    return res.status(500).json({ success: false, message: 'Gagal mengambil data pemain.' });
  }
});

// ===========================================
// ADMIN - ADJUST BALANCE MANUAL
// ============================================
app.post('/api/admin/users/adjust-balance', verifyAdmin, async (req, res) => {
  const userId = Number(req.body?.userId);
  const amount = Number(req.body?.amount);
  const action = String(req.body?.action || '');
  const note = String(req.body?.note || '').trim();

  if (!Number.isInteger(userId) || userId <= 0 || !Number.isFinite(amount) || amount <= 0 || !['add', 'subtract'].includes(action)) {
    return res.status(400).json({ success: false, message: 'Data perubahan saldo tidak valid.' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [rows] = await conn.execute(
      `SELECT id, username, balance, status, role FROM users WHERE id = ? FOR UPDATE`,
      [userId]
    );

    if (rows.length === 0 || rows[0].role === 'admin') {
      await conn.rollback();
      return res.status(404).json({ success: false, message: 'Member tidak ditemukan.' });
    }

    const currentBalance = parseFloat(rows[0].balance || 0);
    let newBalance = currentBalance + amount;

    if (action === 'subtract') {
      newBalance = currentBalance - amount;
      if (newBalance < 0) {
        await conn.rollback();
        return res.status(400).json({ success: false, message: 'Saldo pemain tidak mencukupi.' });
      }
    }

    await conn.execute('UPDATE users SET balance = ? WHERE id = ?', [newBalance, userId]);

    const type = action === 'add' ? 'TOPUP' : 'WITHDRAW';
    const trxCode = generateTrxCode(action === 'add' ? 'ADMDEP' : 'ADMWD');
    const description = note || (action === 'add' ? 'Penambahan saldo oleh Admin' : 'Pengurangan saldo oleh Admin');

    await conn.execute(
      `INSERT INTO transactions
       (user_id, transaction_code, type, amount, status, payment_method, description)
       VALUES (?, ?, ?, ?, 'SUCCESS', 'MANUAL_ADMIN', ?)`,
      [userId, trxCode, type, amount, description]
    );

    await conn.commit();

    return res.json({
      success: true,
      message: `Saldo ${rows[0].username} berhasil diubah! Saldo baru: Rp ${newBalance.toLocaleString('id-ID')}`,
      data: { new_balance: newBalance, newBalance }
    });
  } catch (error) {
    await conn.rollback();
    console.error('Adjust Balance Error:', error);
    return res.status(500).json({ success: false, message: 'Gagal mengubah saldo: ' + error.message });
  } finally {
    conn.release();
  }
});

// =============================================
// ADMIN - UPDATE DATA MEMBER
// =============================================
app.put('/api/admin/users/:id', verifyAdmin, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({
      success: false,
      message: 'ID member tidak valid.'
    });
  }

  const phone = String(req.body?.phone ?? '').trim();
  const bank_name = String(req.body?.bank_name ?? '').trim();
  const account_name = String(req.body?.account_name ?? '').trim();
  const account_number = String(req.body?.account_number ?? '').trim();
  const status = String(req.body?.status ?? '').trim().toLowerCase();

  if (!['active', 'suspended'].includes(status)) {
    return res.status(400).json({
      success: false,
      message: 'Status akun tidak valid.'
    });
  }

  try {
    const [result] = await pool.execute(
      `UPDATE users
       SET
         phone = ?,
         bank_name = ?,
         account_name = ?,
         account_number = ?,
         status = ?
       WHERE id = ?
         AND role != 'admin'`,
      [
        phone,
        bank_name,
        account_name,
        account_number,
        status,
        id
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'Member tidak ditemukan.'
      });
    }

    return res.json({
      success: true,
      message: 'Data member berhasil diperbarui.'
    });

  } catch (error) {
    console.error('Update Member Error:', error);

    return res.status(500).json({
      success: false,
      message: 'Gagal memperbarui data member.'
    });
  }
});

// =============================================
// ADMIN - TOGGLE STATUS
// =============================================
app.post('/api/admin/users/toggle-status', verifyAdmin, async (req, res) => {
  const userId = Number(req.body?.userId);
  const status = String(req.body?.status || '');

  if (!Number.isInteger(userId) || userId <= 0 || !['active', 'suspended'].includes(status)) {
    return res.status(400).json({ success: false, message: 'Status tidak valid!' });
  }

  try {
    const [result] = await pool.execute(
      `UPDATE users SET status = ? WHERE id = ? AND role != 'admin'`,
      [status, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Member tidak ditemukan.' });
    }

    return res.json({ success: true, message: `Status akun berhasil diubah menjadi: ${status.toUpperCase()}` });
  } catch (error) {
    console.error('Toggle Status Error:', error);
    return res.status(500).json({ success: false, message: 'Gagal mengubah status akun.' });
  }
});

// =============================================
// ADMIN - RIWAYAT TRANSAKSI
// ==============================================
app.get('/api/admin/transactions', verifyAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT
         t.id,
         t.transaction_code,
         t.user_id,
         t.type,
         t.amount,
         t.status,
         t.payment_method,
         t.description,
         t.created_at,
         u.username,
         u.phone,
         u.bank_name,
         u.account_name,
         u.account_number
       FROM transactions t
       JOIN users u ON t.user_id = u.id
       WHERE t.type IN ('TOPUP', 'WITHDRAW')
       ORDER BY t.created_at DESC, t.id DESC
       LIMIT 200`
    );

    return res.json({
      success: true,
      count: rows.length,
      data: rows.map(t => ({ ...t, amount: parseFloat(t.amount || 0) }))
    });
  } catch (error) {
    console.error('Admin Transactions Error:', error);
    return res.status(500).json({ success: false, message: 'Gagal mengambil riwayat transaksi.' });
  }
});

// ======================================================
// ADMIN APPROVE TRANSACTION
// ======================================================
app.post('/api/admin/transactions/approve', verifyAdmin, async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const transaction_id =
  req.body?.transaction_id ??
  req.body?.transactionId ??
  req.body?.id;

    if (!transaction_id) {
      return res.status(400).json({
        message: 'transaction_id wajib diisi'
      });
    }

    await conn.beginTransaction();

    // Kunci transaksi
    const [transactions] = await conn.query(
      `SELECT *
       FROM transactions
       WHERE id = ?
       FOR UPDATE`,
      [transaction_id]
    );

    if (transactions.length === 0) {
      await conn.rollback();

      return res.status(404).json({
        message: 'Transaksi tidak ditemukan'
      });
    }

    const transaction = transactions[0];

    if (transaction.status !== 'PENDING') {
      await conn.rollback();

      return res.status(400).json({
        message: 'Transaksi sudah diproses'
      });
    }

    // ==========================================
    // TOP UP
    // Saat approve, saldo baru ditambahkan
    // ==========================================
    if (transaction.type === 'TOPUP') {

      await conn.query(
        `UPDATE users
         SET balance = balance + ?
         WHERE id = ?`,
        [
          Number(transaction.amount),
          transaction.user_id
        ]
      );
    }

    // ==========================================
    // WITHDRAW
    //
    // TIDAK mengurangi saldo lagi.
    // Saldo sudah dipotong ketika member
    // mengajukan withdraw.
    // ==========================================
    if (transaction.type === 'WITHDRAW') {
      // Tidak melakukan perubahan saldo
    }

    // ==========================================
    // UBAH STATUS MENJADI SUCCESS
    // ==========================================
    await conn.query(
      `UPDATE transactions
       SET status = 'SUCCESS'
       WHERE id = ?`,
      [transaction_id]
    );

    await conn.commit();

    return res.json({
      success: true,
      message: 'Transaksi berhasil disetujui'
    });

  } catch (error) {
    await conn.rollback();

    console.error('APPROVE TRANSACTION ERROR:', error);

    return res.status(500).json({
      message: 'Gagal menyetujui transaksi'
    });

  } finally {
    conn.release();
  }
});

// ============================================
// ADMIN REJECT TRANSACTION
// Jika WITHDRAW -> saldo dikembalikan
// Jika TOPUP -> tidak ada perubahan saldo
// =============================================
app.post('/api/admin/transactions/reject', verifyAdmin, async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const transaction_id =
  req.body?.transaction_id ??
  req.body?.transactionId ??
  req.body?.id;

    if (!transaction_id) {
      return res.status(400).json({
        message: 'transaction_id wajib diisi'
      });
    }

    await conn.beginTransaction();

    // Kunci transaksi
    const [transactions] = await conn.query(
      `SELECT *
       FROM transactions
       WHERE id = ?
       FOR UPDATE`,
      [transaction_id]
    );

    if (transactions.length === 0) {
      await conn.rollback();

      return res.status(404).json({
        message: 'Transaksi tidak ditemukan'
      });
    }

    const transaction = transactions[0];

    if (transaction.status !== 'PENDING') {
      await conn.rollback();

      return res.status(400).json({
        message: 'Transaksi sudah diproses'
      });
    }

    // ==========================================
    // JIKA WITHDRAW DITOLAK
    // KEMBALIKAN SALDO MEMBER
    // ==========================================
    if (transaction.type === 'WITHDRAW') {

      await conn.query(
        `UPDATE users
         SET balance = balance + ?
         WHERE id = ?`,
        [
          Number(transaction.amount),
          transaction.user_id
        ]
      );
    }

    // ==========================================
    // JIKA TOPUP DITOLAK
    // Tidak perlu mengubah saldo
    // karena saldo TOPUP belum ditambahkan
    // ==========================================

    // ==========================================
    // UBAH STATUS MENJADI FAILED
    // ==========================================
    await conn.query(
      `UPDATE transactions
       SET status = 'FAILED'
       WHERE id = ?`,
      [transaction_id]
    );

    await conn.commit();

    return res.json({
      success: true,
      message: 'Transaksi berhasil ditolak'
    });

  } catch (error) {
    await conn.rollback();

    console.error('REJECT TRANSACTION ERROR:', error);

    return res.status(500).json({
      message: 'Gagal menolak transaksi'
    });

  } finally {
    conn.release();
  }
});

// ===============================================
// ADMIN SETUP LAMA - DIPERTAHANKAN
// ==============================================
app.get('/api/admin/setup', async (req, res) => {
  try {
    const [existing] = await pool.execute(
      `SELECT id FROM users WHERE username = 'adminbos' LIMIT 1`
    );

    if (existing.length > 0) {
      return res.json({ success: false, message: 'Akun Admin sudah tersedia.' });
    }

    const password = 'adminboss123';
    const passwordHash = await bcrypt.hash(password, 12);

    await pool.execute(
      `INSERT INTO users
       (username, password_hash, phone, bank_name, account_name, account_number,
        balance, status, role)
       VALUES ('adminbos', ?, '08123456789', 'BCA', 'ADMIN PASTIBOS', '00000000', 0, 'active', 'admin')`,
      [passwordHash]
    );

    return res.json({
      success: true,
      message: 'Berhasil membuat akun Admin pertama!',
      credentials: { username: 'adminbos', password }
    });
  } catch (error) {
    console.error('Admin Setup Error:', error);
    return res.status(500).json({ success: false, message: 'Gagal membuat akun admin: ' + error.message });
  }
});

// =========================================================
// ADMIN PAGE ROUTES
// =========================================================
app.get('/admin', (req, res) => res.redirect(302, '/admin.html'));
app.get('/admin.html', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  return res.sendFile(path.join(__dirname, 'admin.html'));
});
app.get('/api/admin-panel', (req, res) => res.redirect(302, '/admin.html'));

// =========================================================
// ERROR HANDLER
// =========================================================
app.use((err, req, res, next) => {
  console.error('Unhandled Server Error:', err);
  if (res.headersSent) return next(err);
  return res.status(500).json({ success: false, message: 'Terjadi kesalahan server.' });
});

module.exports = app;

if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`PASTIBOS server berjalan di port ${PORT}`));
}
