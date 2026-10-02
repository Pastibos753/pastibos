const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// MIDDLEWARE
// ==========================================

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// KONEKSI DATABASE MYSQL / TiDB CLOUD
// ==========================================

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'game_platform',
  port: parseInt(process.env.DB_PORT || '4000', 10),

  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,

  ssl: process.env.DB_HOST &&
       process.env.DB_HOST.includes('tidbcloud.com')
    ? {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true
      }
    : undefined
});

// ==========================================
// MIDDLEWARE VERIFIKASI TOKEN USER
// ==========================================

function verifyToken(req, res, next) {

  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Akses ditolak. Token tidak ditemukan.'
    });
  }

  const token = authHeader.split(' ')[1];

  try {

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || 'pastibos_secret_key_123456789'
    );

    req.user = decoded;

    next();

  } catch (err) {

    return res.status(403).json({
      success: false,
      message: 'Sesi tidak valid atau sudah kadaluarsa.'
    });

  }
}

// ==========================================
// MIDDLEWARE VERIFIKASI ADMIN
// ==========================================

function verifyAdmin(req, res, next) {

  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {

    return res.status(401).json({
      success: false,
      message: 'Akses admin ditolak. Silakan login sebagai admin.'
    });

  }

  const token = authHeader.split(' ')[1];

  try {

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || 'pastibos_secret_key_123456789'
    );

    if (decoded.role !== 'admin') {

      return res.status(403).json({
        success: false,
        message: 'Hanya akun Admin yang diizinkan mengakses panel ini!'
      });

    }

    req.admin = decoded;

    next();

  } catch (err) {

    return res.status(403).json({
      success: false,
      message: 'Sesi admin kadaluarsa. Silakan login ulang.'
    });

  }
}

// ==========================================
// GENERATE KODE TRANSAKSI
// ==========================================

function generateTrxCode(prefix) {

  return `${prefix}-${Date.now()}-${Math.floor(
    100 + Math.random() * 900
  )}`;

}

// ==========================================
// HEALTH CHECK
// ==========================================

app.get('/', (req, res) => {

  res.json({
    status: 'ONLINE',
    message: '🚀 Backend Platform Game PASTIBOS sudah aktif dan siap melayani data.',
    database: 'TiDB Cloud Connected',
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

// ==========================================
// ADMIN SETUP
// ==========================================

app.get('/api/admin/setup', async (req, res) => {

  try {

    const [existing] = await pool.execute(
      "SELECT id FROM users WHERE username = 'adminbos' LIMIT 1"
    );

    if (existing.length > 0) {

      return res.json({
        success: false,
        message: 'Akun Admin sudah tersedia.'
      });

    }

    const salt = await bcrypt.genSalt(10);

    const defaultPassword = 'adminboss123';

    const hashedPassword = await bcrypt.hash(
      defaultPassword,
      salt
    );

    await pool.execute(
      `INSERT INTO users
      (
        username,
        password_hash,
        phone,
        bank_name,
        account_name,
        account_number,
        balance,
        role
      )
      VALUES
      (
        'adminbos',
        ?,
        '08123456789',
        'BCA',
        'ADMIN PASTIBOS',
        '00000000',
        9999999.00,
        'admin'
      )`,
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

    return res.status(500).json({

      success: false,

      message:
        'Gagal membuat akun admin: ' +
        error.message

    });

  }

});

// ==========================================
// LOGIN ADMIN
// ==========================================

app.post('/api/admin/login', async (req, res) => {

  try {

    const {
      username,
      password
    } = req.body;

    if (!username || !password) {

      return res.status(400).json({

        success: false,

        message:
          'Username dan password wajib diisi!'

      });

    }

    const [rows] = await pool.execute(

      `SELECT *
       FROM users
       WHERE username = ?
       AND role = 'admin'
       LIMIT 1`,

      [username]

    );

    if (rows.length === 0) {

      return res.status(401).json({

        success: false,

        message:
          'Akun Admin tidak ditemukan atau bukan berstatus Admin!'

      });

    }

    const admin = rows[0];

    const isMatch = await bcrypt.compare(
      password,
      admin.password_hash
    );

    if (!isMatch) {

      return res.status(401).json({

        success: false,

        message:
          'Password admin salah!'

      });

    }

    const token = jwt.sign(

      {
        id: admin.id,
        username: admin.username,
        role: 'admin'
      },

      process.env.JWT_SECRET ||
        'pastibos_secret_key_123456789',

      {
        expiresIn: '7d'
      }

    );

    return res.status(200).json({

      success: true,

      message:
        'Login Admin Berhasil!',

      data: {

        token,

        username: admin.username

      }

    });

  } catch (error) {

    console.error(
      'Admin Login Error:',
      error
    );

    return res.status(500).json({

      success: false,

      message:
        'Server error saat login admin.'

    });

  }

});

// ==========================================
// AMBIL SEMUA PEMAIN
// ==========================================

app.get(
  '/api/admin/users',
  verifyAdmin,
  async (req, res) => {

    try {

      const [rows] = await pool.execute(

        `SELECT
          id,
          username,
          phone,
          bank_name,
          account_name,
          account_number,
          referral_code,
          balance,
          status,
          role,
          created_at

        FROM users

        WHERE role != 'admin'

        ORDER BY created_at DESC`

      );

      const formatted = rows.map(u => ({

        ...u,

        balance:
          parseFloat(u.balance)

      }));

      return res.json({

        success: true,

        count:
          formatted.length,

        data:
          formatted

      });

    } catch (error) {

      console.error(
        'Get Users Error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Gagal mengambil data pemain.'

      });

    }

  }
);

// ==========================================
// TAMBAH / KURANGI SALDO
// ==========================================

app.post(
  '/api/admin/users/adjust-balance',
  verifyAdmin,
  async (req, res) => {

    const {
      userId,
      amount,
      action,
      note
    } = req.body;

    const nominal =
      parseFloat(amount);

    if (
      !userId ||
      isNaN(nominal) ||
      nominal <= 0 ||
      !['add', 'subtract'].includes(action)
    ) {

      return res.status(400).json({

        success: false,

        message:
          'Data perubahan saldo tidak valid.'

      });

    }

    const conn =
      await pool.getConnection();

    try {

      await conn.beginTransaction();

      const [rows] =
        await conn.execute(

          `SELECT
            id,
            username,
            balance

           FROM users

           WHERE id = ?

           AND role != 'admin'

           FOR UPDATE`,

          [userId]

        );

      if (rows.length === 0) {

        await conn.rollback();

        return res.status(404).json({

          success: false,

          message:
            'Pemain tidak ditemukan.'

        });

      }

      const currentBalance =
        parseFloat(rows[0].balance || 0);

      let newBalance;

      if (action === 'add') {

        newBalance =
          currentBalance + nominal;

      } else {

        newBalance =
          currentBalance - nominal;

        if (newBalance < 0) {

          await conn.rollback();

          return res.status(400).json({

            success: false,

            message:
              'Saldo pemain tidak mencukupi.'

          });

        }

      }

      await conn.execute(

        `UPDATE users
         SET balance = ?
         WHERE id = ?`,

        [
          newBalance,
          userId
        ]

      );

      const trxCode =
        generateTrxCode(
          action === 'add'
            ? 'ADMDEP'
            : 'ADMWD'
        );

      const trxType =
        action === 'add'
          ? 'DEPOSIT'
          : 'WITHDRAW';

      const description =
        note ||
        (
          action === 'add'
            ? 'Penambahan saldo oleh Admin'
            : 'Pengurangan saldo oleh Admin'
        );

      await conn.execute(

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

        VALUES
        (
          ?,
          ?,
          ?,
          ?,
          'SUCCESS',
          'MANUAL_ADMIN',
          ?
        )`,

        [
          userId,
          trxCode,
          trxType,
          nominal,
          description
        ]

      );

      await conn.commit();

      return res.json({

        success: true,

        message:
          `Saldo ${rows[0].username} berhasil diubah! Saldo baru: Rp ${newBalance.toLocaleString('id-ID')}`,

        data: {

          newBalance

        }

      });

    } catch (error) {

      await conn.rollback();

      console.error(
        'Adjust Balance Error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Gagal mengubah saldo: ' +
          error.message

      });

    } finally {

      conn.release();

    }

  }
);

// ==========================================
// AKTIFKAN / BLOKIR AKUN
// ==========================================

app.post(
  '/api/admin/users/toggle-status',
  verifyAdmin,
  async (req, res) => {

    const {
      userId,
      status
    } = req.body;

    if (
      !userId ||
      !['active', 'suspended'].includes(status)
    ) {

      return res.status(400).json({

        success: false,

        message:
          'Status tidak valid!'

      });

    }

    try {

      await pool.execute(

        `UPDATE users
         SET status = ?
         WHERE id = ?`,

        [
          status,
          userId
        ]

      );

      return res.json({

        success: true,

        message:
          `Status akun berhasil diubah menjadi: ${status.toUpperCase()}`

      });

    } catch (error) {

      console.error(
        'Toggle Status Error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Gagal mengubah status akun.'

      });

    }

  }
);

// ==========================================
// RIWAYAT TRANSAKSI ADMIN
// ==========================================

app.get(
  '/api/admin/transactions',
  verifyAdmin,
  async (req, res) => {

    try {

      const [rows] =
        await pool.execute(

          `SELECT
            t.id,
            t.transaction_code,
            t.type,
            t.amount,
            t.status,
            t.payment_method,
            t.description,
            t.created_at,
            u.username,
            u.bank_name,
            u.account_number

           FROM transactions t

           JOIN users u
             ON t.user_id = u.id

           ORDER BY
             t.created_at DESC

           LIMIT 100`

        );

      const formatted =
        rows.map(t => ({

          ...t,

          amount:
            parseFloat(t.amount)

        }));

      return res.json({

        success: true,

        count:
          formatted.length,

        data:
          formatted

      });

    } catch (error) {

      console.error(
        'Transactions Error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Gagal mengambil riwayat transaksi.'

      });

    }

  }
);

// ==========================================
// HALAMAN ADMIN
// ==========================================
// DESAIN ADMIN SEKARANG DIAMBIL DARI
// FILE admin.html TERPISAH.
//
// Struktur:
//
// /server.js
// /admin.html
// /package.json
// /vercel.json
//
// ==========================================

// /admin
// diarahkan ke admin.html

app.get('/admin', (req, res) => {

  return res.redirect(
    302,
    '/admin.html'
  );

});

// /admin.html
// fallback jika request masuk melalui Express

app.get('/admin.html', (req, res) => {

  res.setHeader(
    'Cache-Control',
    'no-store'
  );

  return res.sendFile(
    path.join(
      __dirname,
      'admin.html'
    )
  );

});

// Endpoint lama tetap diarahkan
// ke halaman admin baru

app.get('/api/admin-panel', (req, res) => {

  return res.redirect(
    302,
    '/admin.html'
  );

});


// ==========================================
// REGISTER MEMBER
// ==========================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, phone, bank_name, account_name, account_number, referral_code } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username dan password wajib diisi!' });
    }

    // Cek apakah username sudah ada
    const [existing] = await pool.execute("SELECT id FROM users WHERE username = ? LIMIT 1", [username]);
    if (existing.length > 0) {
      return res.status(400).json({ success: false, message: 'Username sudah digunakan!' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await pool.execute(
      `INSERT INTO users (username, password_hash, phone, bank_name, account_name, account_number, referral_code, balance, status, role)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0.00, 'active', 'member')`,
      [username, hashedPassword, phone || '', bank_name || '', account_name || '', account_number || '', referral_code || '']
    );

    return res.json({ success: true, message: 'Registrasi berhasil! Silakan login.' });
  } catch (error) {
    console.error('Register Error:', error);
    return res.status(500).json({ success: false, message: 'Server error saat registrasi.' });
  }
});

// ==========================================
// LOGIN MEMBER
// ==========================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username dan password wajib diisi!' });
    }

    const [rows] = await pool.execute("SELECT * FROM users WHERE username = ? LIMIT 1", [username]);
    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Username tidak ditemukan!' });
    }

    const user = rows[0];

    if (user.status === 'suspended') {
      return res.status(403).json({ success: false, message: 'Akun Anda telah diblokir/suspended.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Kata sandi salah!' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'pastibos_secret_key_123456789',
      { expiresIn: '7d' }
    );

    return res.json({
      success: true,
      message: 'Login Berhasil!',
      data: {
        token,
        user: {
          id: user.id,
          username: user.username,
          balance: parseFloat(user.balance || 0)
        }
      }
    });
  } catch (error) {
    console.error('Login Error:', error);
    return res.status(500).json({ success: false, message: 'Server error saat login.' });
  }
});

// ==========================================
// EXPORT APP UNTUK VERCEL
// ==========================================

module.exports = app;

// ==========================================
// LOCAL DEVELOPMENT
// ==========================================

if (
  process.env.NODE_ENV !== 'production'
) {

  app.listen(
    PORT,
    () => {

      console.log(
        `Server berjalan di port ${PORT}`
      );

    }
  );

}
