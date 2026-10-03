const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ======================================================
// MIDDLEWARE
// ======================================================

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ======================================================
// DATABASE MYSQL / TiDB CLOUD
// ======================================================

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'game_platform',
  port: parseInt(process.env.DB_PORT || '4000', 10),

  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,

  ssl:
    process.env.DB_HOST &&
    process.env.DB_HOST.includes('tidbcloud.com')
      ? {
          minVersion: 'TLSv1.2',
          rejectUnauthorized: true
        }
      : undefined
});

// ======================================================
// JWT SECRET
// ======================================================

const JWT_SECRET =
  process.env.JWT_SECRET ||
  'pastibos_secret_key_123456789';

// ======================================================
// HELPER
// ======================================================

function generateTrxCode(prefix) {
  return `${prefix}-${Date.now()}-${Math.floor(
    100 + Math.random() * 900
  )}`;
}

function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    phone: row.phone || '',
    bank_name: row.bank_name || '',
    account_name: row.account_name || '',
    account_number: row.account_number || '',
    referral_code: row.referral_code || null,
    balance: Number(row.balance || 0),
    status: row.status || 'active',
    role: row.role || 'member',
    created_at: row.created_at || null
  };
}

// ======================================================
// VERIFY MEMBER TOKEN
// ======================================================

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
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      message: 'Sesi tidak valid atau sudah kadaluarsa.'
    });
  }
}

// ======================================================
// VERIFY ADMIN
// ======================================================

function verifyAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message:
        'Akses admin ditolak. Silakan login sebagai admin.'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message:
          'Hanya akun Admin yang diizinkan mengakses panel ini!'
      });
    }

    req.admin = decoded;

    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      message:
        'Sesi admin kadaluarsa. Silakan login ulang.'
    });
  }
}

// ======================================================
// HEALTH CHECK
// ======================================================

app.get('/', (req, res) => {
  res.json({
    status: 'ONLINE',
    message:
      '🚀 Backend Platform Game PASTIBOS sudah aktif dan siap melayani data.',
    database: 'TiDB Cloud',
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

// ======================================================
// MEMBER REGISTER
// Kompatibel dengan Daftar2.html
// ======================================================

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

    const cleanUsername =
      String(username || '').trim();

    const cleanPhone =
      String(phone || '').trim();

    const cleanBank =
      String(bank || '').trim();

    const cleanAccountName =
      String(namaRek || '').trim();

    const cleanAccountNumber =
      String(noRek || '').trim();

    const cleanReferral =
      String(referral || '').trim();

    if (
      !cleanUsername ||
      !password ||
      !cleanPhone ||
      !cleanBank ||
      !cleanAccountName ||
      !cleanAccountNumber
    ) {
      return res.status(400).json({
        success: false,
        message:
          'Semua data wajib diisi kecuali kode referral.'
      });
    }

    if (
      cleanUsername.length < 3 ||
      cleanUsername.length > 40
    ) {
      return res.status(400).json({
        success: false,
        message:
          'Username harus terdiri dari 3 sampai 40 karakter.'
      });
    }

    if (
      String(password).length < 6 ||
      String(password).length > 128
    ) {
      return res.status(400).json({
        success: false,
        message:
          'Password harus terdiri dari minimal 6 karakter.'
      });
    }

    const [existing] =
      await pool.execute(
        `
        SELECT id
        FROM users
        WHERE username = ?
        LIMIT 1
        `,
        [cleanUsername]
      );

    if (existing.length > 0) {
      return res.status(409).json({
        success: false,
        message:
          'Username sudah terdaftar. Silakan gunakan username lain.'
      });
    }

    const passwordHash =
      await bcrypt.hash(
        String(password),
        12
      );

    const [result] =
      await pool.execute(
        `
        INSERT INTO users
        (
          username,
          password_hash,
          phone,
          bank_name,
          account_name,
          account_number,
          referral_code,
          balance,
          status,
          role
        )
        VALUES
        (
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          0,
          'active',
          'member'
        )
        `,
        [
          cleanUsername,
          passwordHash,
          cleanPhone,
          cleanBank,
          cleanAccountName,
          cleanAccountNumber,
          cleanReferral || null
        ]
      );

    const [createdRows] =
      await pool.execute(
        `
        SELECT
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
        WHERE id = ?
        LIMIT 1
        `,
        [result.insertId]
      );

    if (!createdRows.length) {
      return res.status(500).json({
        success: false,
        message:
          'Member berhasil dibuat tetapi data tidak dapat dibaca kembali.'
      });
    }

    const user =
      publicUser(createdRows[0]);

    const token =
      jwt.sign(
        {
          id: user.id,
          username: user.username,
          role: 'member'
        },
        JWT_SECRET,
        {
          expiresIn: '7d'
        }
      );

    return res.status(201).json({
      success: true,
      message:
        'Pendaftaran berhasil! Selamat datang di PASTIBOS.',
      data: {
        token,
        user
      }
    });

  } catch (error) {

    console.error(
      'Member Register Error:',
      error
    );

    if (
      error &&
      error.code === 'ER_DUP_ENTRY'
    ) {
      return res.status(409).json({
        success: false,
        message:
          'Username sudah terdaftar. Silakan gunakan username lain.'
      });
    }

    return res.status(500).json({
      success: false,
      message:
        'Pendaftaran gagal karena terjadi kesalahan server/database.'
    });
  }
});

// ======================================================
// MEMBER LOGIN
// Kompatibel dengan index.html
// ======================================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const username =
      String(
        (req.body || {}).username || ''
      ).trim();

    const password =
      (req.body || {}).password;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message:
          'Username dan password wajib diisi.'
      });
    }

    const [rows] =
      await pool.execute(
        `
        SELECT
          id,
          username,
          password_hash,
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
        WHERE username = ?
        LIMIT 1
        `,
        [username]
      );

    if (!rows.length) {
      return res.status(401).json({
        success: false,
        message:
          'Username atau password salah.'
      });
    }

    const row = rows[0];

    const passwordMatch =
      await bcrypt.compare(
        String(password),
        row.password_hash || ''
      );

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message:
          'Username atau password salah.'
      });
    }

    if (
      String(row.role || 'member')
        .toLowerCase() === 'admin'
    ) {
      return res.status(403).json({
        success: false,
        message:
          'Gunakan halaman login Admin untuk akun Admin.'
      });
    }

    if (
      String(row.status || 'active')
        .toLowerCase() !== 'active'
    ) {
      return res.status(403).json({
        success: false,
        message:
          'Akun sedang dinonaktifkan. Hubungi Admin.'
      });
    }

    const user =
      publicUser(row);

    const token =
      jwt.sign(
        {
          id: user.id,
          username: user.username,
          role: 'member'
        },
        JWT_SECRET,
        {
          expiresIn: '7d'
        }
      );

    return res.json({
      success: true,
      message: 'Login berhasil.',
      data: {
        token,
        user
      }
    });

  } catch (error) {

    console.error(
      'Member Login Error:',
      error
    );

    return res.status(500).json({
      success: false,
      message:
        'Login gagal karena terjadi kesalahan server/database.'
    });
  }
});

// ======================================================
// MEMBER - CEK PROFILE
// ======================================================

app.get(
  '/api/auth/me',
  verifyToken,
  async (req, res) => {

    try {

      const [rows] =
        await pool.execute(
          `
          SELECT
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
          WHERE id = ?
          LIMIT 1
          `,
          [req.user.id]
        );

      if (!rows.length) {
        return res.status(404).json({
          success: false,
          message:
            'Data member tidak ditemukan.'
        });
      }

      return res.json({
        success: true,
        data: {
          user: publicUser(rows[0])
        }
      });

    } catch (error) {

      console.error(
        'Get Profile Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Gagal mengambil data profile.'
      });
    }
  }
);

// ======================================================
// ADMIN SETUP
// ======================================================

app.get('/api/admin/setup', async (req, res) => {

  const setupKey =
    req.headers['x-admin-setup-key'];

  if (
    !process.env.ADMIN_SETUP_KEY ||
    setupKey !== process.env.ADMIN_SETUP_KEY
  ) {
    return res.status(403).json({
      success: false,
      message:
        'Setup Admin tidak diizinkan.'
    });
  }

  const username =
    String(
      process.env.ADMIN_INITIAL_USERNAME ||
      'adminbos'
    ).trim();

  const password =
    process.env.ADMIN_INITIAL_PASSWORD;

  if (
    !password ||
    String(password).length < 12
  ) {
    return res.status(500).json({
      success: false,
      message:
        'Atur ADMIN_INITIAL_PASSWORD minimal 12 karakter di Environment Variables.'
    });
  }

  try {

    const [existing] =
      await pool.execute(
        `
        SELECT id
        FROM users
        WHERE username = ?
        LIMIT 1
        `,
        [username]
      );

    if (existing.length) {
      return res.status(409).json({
        success: false,
        message:
          'Username Admin sudah tersedia.'
      });
    }

    const passwordHash =
      await bcrypt.hash(
        String(password),
        12
      );

    await pool.execute(
      `
      INSERT INTO users
      (
        username,
        password_hash,
        phone,
        bank_name,
        account_name,
        account_number,
        balance,
        status,
        role
      )
      VALUES
      (
        ?,
        ?,
        ?,
        'ADMIN',
        'ADMIN PASTIBOS',
        'ADMIN',
        0,
        'active',
        'admin'
      )
      `,
      [
        username,
        passwordHash,
        ''
      ]
    );

    return res.status(201).json({
      success: true,
      message:
        'Akun Admin awal berhasil dibuat.',
      data: {
        username
      }
    });

  } catch (error) {

    console.error(
      'Admin Setup Error:',
      error
    );

    return res.status(500).json({
      success: false,
      message:
        'Gagal membuat akun Admin.'
    });
  }
});

// ======================================================
// ADMIN LOGIN
// Kompatibel dengan admin.html
// ======================================================

app.post(
  '/api/admin/login',
  async (req, res) => {

    try {

      const {
        username,
        password
      } = req.body || {};

      if (!username || !password) {
        return res.status(400).json({
          success: false,
          message:
            'Username dan password wajib diisi!'
        });
      }

      const [rows] =
        await pool.execute(
          `
          SELECT *
          FROM users
          WHERE username = ?
          AND role = 'admin'
          LIMIT 1
          `,
          [username]
        );

      if (!rows.length) {
        return res.status(401).json({
          success: false,
          message:
            'Akun Admin tidak ditemukan atau bukan berstatus Admin!'
        });
      }

      const admin =
        rows[0];

      const passwordMatch =
        await bcrypt.compare(
          String(password),
          admin.password_hash || ''
        );

      if (!passwordMatch) {
        return res.status(401).json({
          success: false,
          message:
            'Password admin salah!'
        });
      }

      if (
        String(admin.status || 'active')
          .toLowerCase() !== 'active'
      ) {
        return res.status(403).json({
          success: false,
          message:
            'Akun Admin sedang tidak aktif.'
        });
      }

      const token =
        jwt.sign(
          {
            id: admin.id,
            username: admin.username,
            role: 'admin'
          },
          JWT_SECRET,
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
  }
);

// ======================================================
// ADMIN - AMBIL SEMUA MEMBER
// ======================================================

app.get(
  '/api/admin/users',
  verifyAdmin,
  async (req, res) => {

    try {

      const [rows] =
        await pool.execute(
          `
          SELECT
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
          ORDER BY created_at DESC
          `
        );

      const formatted =
        rows.map(user => ({
          ...user,
          balance:
            Number(user.balance || 0)
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

// ======================================================
// ADMIN - DETAIL MEMBER
// ======================================================

app.get(
  '/api/admin/users/:id',
  verifyAdmin,
  async (req, res) => {

    try {

      const userId =
        Number(req.params.id);

      if (
        !Number.isInteger(userId) ||
        userId <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            'ID member tidak valid.'
        });
      }

      const [rows] =
        await pool.execute(
          `
          SELECT
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
          WHERE id = ?
          AND role != 'admin'
          LIMIT 1
          `,
          [userId]
        );

      if (!rows.length) {
        return res.status(404).json({
          success: false,
          message:
            'Member tidak ditemukan.'
        });
      }

      return res.json({
        success: true,
        data:
          publicUser(rows[0])
      });

    } catch (error) {

      console.error(
        'Get User Detail Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Gagal mengambil detail member.'
      });
    }
  }
);

// ======================================================
// ADMIN - TAMBAH / KURANGI SALDO
// ======================================================

app.post(
  '/api/admin/users/adjust-balance',
  verifyAdmin,
  async (req, res) => {

    const {
      userId,
      amount,
      action,
      note
    } = req.body || {};

    const userIdNumber =
      Number(userId);

    const nominal =
      Number(amount);

    if (
      !Number.isInteger(userIdNumber) ||
      userIdNumber <= 0 ||
      !Number.isFinite(nominal) ||
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
          `
          SELECT
            id,
            username,
            balance
          FROM users
          WHERE id = ?
          AND role != 'admin'
          FOR UPDATE
          `,
          [userIdNumber]
        );

      if (!rows.length) {

        await conn.rollback();

        return res.status(404).json({
          success: false,
          message:
            'Pemain tidak ditemukan.'
        });
      }

      const currentBalance =
        Number(rows[0].balance || 0);

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
        `
        UPDATE users
        SET balance = ?
        WHERE id = ?
        `,
        [
          newBalance,
          userIdNumber
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
          ? 'TOPUP'
          : 'WITHDRAW';

      const description =
        note ||
        (
          action === 'add'
            ? 'Penambahan saldo oleh Admin'
            : 'Pengurangan saldo oleh Admin'
        );

      await conn.execute(
        `
        INSERT INTO transactions
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
        )
        `,
        [
          userIdNumber,
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

// ======================================================
// ADMIN - AKTIFKAN / BLOKIR MEMBER
// ======================================================

app.post(
  '/api/admin/users/toggle-status',
  verifyAdmin,
  async (req, res) => {

    const {
      userId,
      status
    } = req.body || {};

    const userIdNumber =
      Number(userId);

    if (
      !Number.isInteger(userIdNumber) ||
      userIdNumber <= 0 ||
      !['active', 'suspended'].includes(status)
    ) {
      return res.status(400).json({
        success: false,
        message:
          'Status tidak valid!'
      });
    }

    try {

      const [result] =
        await pool.execute(
          `
          UPDATE users
          SET status = ?
          WHERE id = ?
          AND role != 'admin'
          `,
          [
            status,
            userIdNumber
          ]
        );

      if (!result.affectedRows) {
        return res.status(404).json({
          success: false,
          message:
            'Member tidak ditemukan.'
        });
      }

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

// ======================================================
// ADMIN - RIWAYAT TRANSAKSI
// ======================================================

app.get(
  '/api/admin/transactions',
  verifyAdmin,
  async (req, res) => {

    try {

      const [rows] =
        await pool.execute(
          `
          SELECT
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
          LIMIT 100
          `
        );

      const formatted =
        rows.map(t => ({
          ...t,
          amount:
            Number(t.amount || 0)
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

// ======================================================
// ADMIN - APPROVE DEPOSIT
// ======================================================

app.post(
  '/api/admin/transactions/approve',
  verifyAdmin,
  async (req, res) => {

    const transactionId =
      Number(
        (req.body || {}).transactionId ||
        (req.body || {}).id
      );

    if (
      !Number.isInteger(transactionId) ||
      transactionId <= 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          'ID transaksi tidak valid.'
      });
    }

    const conn =
      await pool.getConnection();

    try {

      await conn.beginTransaction();

      const [rows] =
        await conn.execute(
          `
          SELECT
            id,
            user_id,
            type,
            amount,
            status
          FROM transactions
          WHERE id = ?
          FOR UPDATE
          `,
          [transactionId]
        );

      if (!rows.length) {

        await conn.rollback();

        return res.status(404).json({
          success: false,
          message:
            'Transaksi tidak ditemukan.'
        });
      }

      const trx =
        rows[0];

      if (
        String(trx.type)
          .toUpperCase() !== 'TOPUP'
      ) {

        await conn.rollback();

        return res.status(400).json({
          success: false,
          message:
            'Transaksi ini bukan deposit.'
        });
      }

      if (
        String(trx.status)
          .toUpperCase() !== 'PENDING'
      ) {

        await conn.rollback();

        return res.status(409).json({
          success: false,
          message:
            'Transaksi sudah diproses sebelumnya.'
        });
      }

      const amount =
        Number(trx.amount);

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {

        await conn.rollback();

        return res.status(400).json({
          success: false,
          message:
            'Nominal deposit tidak valid.'
        });
      }

      const [userRows] =
        await conn.execute(
          `
          SELECT
            id,
            status
          FROM users
          WHERE id = ?
          AND role != 'admin'
          FOR UPDATE
          `,
          [trx.user_id]
        );

      if (!userRows.length) {

        await conn.rollback();

        return res.status(404).json({
          success: false,
          message:
            'Member pemilik transaksi tidak ditemukan.'
        });
      }

      if (
        String(userRows[0].status)
          .toLowerCase() !== 'active'
      ) {

        await conn.rollback();

        return res.status(400).json({
          success: false,
          message:
            'Akun member sedang tidak aktif.'
        });
      }

      await conn.execute(
        `
        UPDATE users
        SET balance = balance + ?
        WHERE id = ?
        `,
        [
          amount,
          trx.user_id
        ]
      );

      await conn.execute(
        `
        UPDATE transactions
        SET status = 'SUCCESS'
        WHERE id = ?
        AND status = 'PENDING'
        `,
        [transactionId]
      );

      await conn.commit();

      return res.json({
        success: true,
        message:
          'Deposit disetujui dan saldo member berhasil ditambahkan.'
      });

    } catch (error) {

      await conn.rollback();

      console.error(
        'Approve Deposit Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Gagal menyetujui deposit.'
      });

    } finally {

      conn.release();
    }
  }
);

// ======================================================
// ADMIN - REJECT DEPOSIT
// ======================================================

app.post(
  '/api/admin/transactions/reject',
  verifyAdmin,
  async (req, res) => {

    const transactionId =
      Number(
        (req.body || {}).transactionId ||
        (req.body || {}).id
      );

    if (
      !Number.isInteger(transactionId) ||
      transactionId <= 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          'ID transaksi tidak valid.'
      });
    }

    try {

      const [result] =
        await pool.execute(
          `
          UPDATE transactions
          SET status = 'REJECTED'
          WHERE id = ?
          AND type = 'TOPUP'
          AND status = 'PENDING'
          `,
          [transactionId]
        );

      if (!result.affectedRows) {
        return res.status(404).json({
          success: false,
          message:
            'Deposit pending tidak ditemukan atau sudah diproses.'
        });
      }

      return res.json({
        success: true,
        message:
          'Deposit berhasil ditolak.'
      });

    } catch (error) {

      console.error(
        'Reject Deposit Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Gagal menolak deposit.'
      });
    }
  }
);

// ======================================================
// ADMIN - STATISTIK SINGKAT
// ======================================================

app.get(
  '/api/admin/stats',
  verifyAdmin,
  async (req, res) => {

    try {

      const [users] =
        await pool.execute(
          `
          SELECT
            COUNT(*) AS total_users,
            COALESCE(
              SUM(balance),
              0
            ) AS total_balance
          FROM users
          WHERE role != 'admin'
          `
        );

      const [pending] =
        await pool.execute(
          `
          SELECT
            COUNT(*) AS pending_deposits
          FROM transactions
          WHERE type = 'TOPUP'
          AND status = 'PENDING'
          `
        );

      return res.json({
        success: true,
        data: {
          total_users:
            Number(users[0].total_users || 0),

          total_balance:
            Number(users[0].total_balance || 0),

          pending_deposits:
            Number(
              pending[0].pending_deposits || 0
            )
        }
      });

    } catch (error) {

      console.error(
        'Admin Stats Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Gagal mengambil statistik Admin.'
      });
    }
  }
);

// ======================================================
// HALAMAN ADMIN
// ======================================================

app.get('/admin', (req, res) => {
  return res.redirect(
    302,
    '/admin.html'
  );
});

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

app.get('/api/admin-panel', (req, res) => {
  return res.redirect(
    302,
    '/admin.html'
  );
});

// ======================================================
// ERROR HANDLER
// ======================================================

app.use(
  (err, req, res, next) => {

    console.error(
      'Unhandled Server Error:',
      err
    );

    return res.status(500).json({
      success: false,
      message:
        'Terjadi kesalahan internal pada server.'
    });
  }
);

// ======================================================
// EXPORT UNTUK VERCEL
// ======================================================

module.exports = app;

// ======================================================
// LOCAL DEVELOPMENT
// ======================================================

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
