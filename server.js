const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

/*
==================================================
 PASTIBOS BACKEND
 Sesuai struktur TiDB Cloud yang digunakan:
 users.role:
   - admin
   - user

 transactions.type:
   - TOPUP
   - WITHDRAW
   - GAME_BET
   - GAME_WIN
   - MANUAL_TRANSFER

 transactions.status:
   - PENDING
   - SUCCESS
   - FAILED
==================================================
*/


// ==================================================
// MIDDLEWARE
// ==================================================

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// ==================================================
// DATABASE TiDB CLOUD
// ==================================================

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


// ==================================================
// JWT
// ==================================================

const JWT_SECRET =
  process.env.JWT_SECRET ||
  'pastibos_secret_key_123456789';


// ==================================================
// HELPER
// ==================================================

function generateTrxCode(prefix = 'TRX') {
  return `${prefix}-${Date.now()}-${Math.floor(
    100 + Math.random() * 900
  )}`;
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
    role: user.role || 'user',
    created_at: user.created_at || null
  };
}


// ==================================================
// TOKEN USER
// ==================================================

function verifyToken(req, res, next) {

  const authHeader = req.headers.authorization;

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
      JWT_SECRET
    );

    req.user = decoded;

    next();

  } catch (error) {

    return res.status(403).json({
      success: false,
      message: 'Sesi tidak valid atau sudah kadaluarsa.'
    });

  }
}


// ==================================================
// TOKEN ADMIN
// ==================================================

function verifyAdmin(req, res, next) {

  const authHeader = req.headers.authorization;

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
      JWT_SECRET
    );

    if (decoded.role !== 'admin') {

      return res.status(403).json({
        success: false,
        message: 'Hanya akun Admin yang diizinkan mengakses panel ini!'
      });

    }

    req.admin = decoded;

    next();

  } catch (error) {

    return res.status(403).json({
      success: false,
      message: 'Sesi admin kadaluarsa. Silakan login ulang.'
    });

  }
}


// ==================================================
// HEALTH CHECK
// ==================================================

app.get('/', (req, res) => {

  res.json({
    status: 'ONLINE',
    message: 'Backend PASTIBOS aktif.',
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


// ==================================================
// MEMBER REGISTER
// ==================================================

app.post('/api/auth/register', async (req, res) => {

  const {
    username,
    password,
    phone,
    bank,
    namaRek,
    noRek,
    referral
  } = req.body || {};

  try {

    if (!username || !password) {

      return res.status(400).json({
        success: false,
        message: 'Username dan password wajib diisi.'
      });

    }

    if (username.length < 3) {

      return res.status(400).json({
        success: false,
        message: 'Username minimal 3 karakter.'
      });

    }

    if (password.length < 6) {

      return res.status(400).json({
        success: false,
        message: 'Password minimal 6 karakter.'
      });

    }


    // ----------------------------------------------
    // CEK USERNAME
    // ----------------------------------------------

    const [existing] = await pool.execute(
      `
      SELECT id
      FROM users
      WHERE username = ?
      LIMIT 1
      `,
      [username]
    );

    if (existing.length > 0) {

      return res.status(409).json({
        success: false,
        message: 'Username sudah terdaftar.'
      });

    }


    // ----------------------------------------------
    // HASH PASSWORD
    // ----------------------------------------------

    const passwordHash = await bcrypt.hash(
      password,
      12
    );


    // ----------------------------------------------
    // INSERT MEMBER
    //
    // PENTING:
    // role = 'user'
    // bukan 'member'
    // ----------------------------------------------

    const [result] = await pool.execute(
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
        'user'
      )
      `,
      [
        username,
        passwordHash,
        phone || '',
        bank || '',
        namaRek || '',
        noRek || '',
        referral || ''
      ]
    );


    // ----------------------------------------------
    // AMBIL USER BARU
    // ----------------------------------------------

    const [rows] = await pool.execute(
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


    const user = rows[0];


    // ----------------------------------------------
    // TOKEN
    // ----------------------------------------------

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: 'user'
      },
      JWT_SECRET,
      {
        expiresIn: '7d'
      }
    );


    console.log(
      'Member Register Success:',
      username
    );


    return res.status(201).json({

      success: true,

      message:
        'Pendaftaran berhasil! Akun Anda sudah dibuat.',

      data: {
        token,
        user: publicUser(user)
      }

    });


  } catch (error) {

    console.error(
      'Member Register Error:',
      error
    );

    return res.status(500).json({

      success: false,

      message:
        'Pendaftaran gagal karena terjadi kesalahan server/database.'

    });

  }

});


// ==================================================
// MEMBER LOGIN
// ==================================================

app.post('/api/auth/login', async (req, res) => {

  const {
    username,
    password
  } = req.body || {};

  try {

    if (!username || !password) {

      return res.status(400).json({
        success: false,
        message: 'Username dan password wajib diisi.'
      });

    }


    const [rows] = await pool.execute(
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


    if (rows.length === 0) {

      return res.status(401).json({
        success: false,
        message: 'Username atau password salah.'
      });

    }


    const user = rows[0];


    const passwordMatch =
      await bcrypt.compare(
        password,
        user.password_hash
      );


    if (!passwordMatch) {

      return res.status(401).json({
        success: false,
        message: 'Username atau password salah.'
      });

    }


    if (user.role === 'admin') {

      return res.status(403).json({
        success: false,
        message: 'Gunakan halaman Login Admin untuk akun Admin.'
      });

    }


    if (
      user.status &&
      user.status.toLowerCase() !== 'active'
    ) {

      return res.status(403).json({
        success: false,
        message: 'Akun Anda sedang ditangguhkan.'
      });

    }


    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: 'user'
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
        user: publicUser(user)
      }

    });


  } catch (error) {

    console.error(
      'Member Login Error:',
      error
    );

    return res.status(500).json({

      success: false,

      message: 'Server error saat login member.'

    });

  }

});


// ==================================================
// MEMBER - DATA AKUN
// ==================================================

app.get(
  '/api/auth/me',
  verifyToken,
  async (req, res) => {

    try {

      const [rows] = await pool.execute(
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


      if (rows.length === 0) {

        return res.status(404).json({
          success: false,
          message: 'User tidak ditemukan.'
        });

      }


      return res.json({
        success: true,
        data: publicUser(rows[0])
      });


    } catch (error) {

      console.error(
        'Auth Me Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message: 'Gagal mengambil data akun.'
      });

    }

  }
);


// ==================================================
// MEMBER - BUAT DEPOSIT / TOPUP
//
// Deposit:
// PENDING
// Saldo TIDAK bertambah.
// Admin harus APPROVE.
// ==================================================

app.post(
  '/api/transactions/deposit',
  verifyToken,
  async (req, res) => {

    const {
      amount,
      payment_method,
      paymentMethod,
      description
    } = req.body || {};

    const nominal = parseFloat(amount);

    const method =
      payment_method ||
      paymentMethod ||
      'MANUAL_TRANSFER';


    try {

      if (
        !nominal ||
        isNaN(nominal) ||
        nominal <= 0
      ) {

        return res.status(400).json({
          success: false,
          message: 'Nominal deposit tidak valid.'
        });

      }


      // Hanya user/member
      if (req.user.role === 'admin') {

        return res.status(403).json({
          success: false,
          message: 'Admin tidak dapat membuat deposit member.'
        });

      }


      // Pastikan user masih aktif
      const [users] = await pool.execute(
        `
        SELECT
          id,
          username,
          status
        FROM users
        WHERE id = ?
        LIMIT 1
        `,
        [req.user.id]
      );


      if (users.length === 0) {

        return res.status(404).json({
          success: false,
          message: 'Akun tidak ditemukan.'
        });

      }


      if (
        users[0].status &&
        users[0].status.toLowerCase() !== 'active'
      ) {

        return res.status(403).json({
          success: false,
          message: 'Akun Anda tidak aktif.'
        });

      }


      const trxCode =
        generateTrxCode('DEP');


      const [result] = await pool.execute(
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
          'TOPUP',
          ?,
          'PENDING',
          ?,
          ?
        )
        `,
        [
          req.user.id,
          trxCode,
          nominal,
          method,
          description ||
            'Permintaan deposit member'
        ]
      );


      return res.status(201).json({

        success: true,

        message:
          'Deposit berhasil diajukan dan menunggu persetujuan Admin.',

        data: {
          id: result.insertId,
          transactionId: result.insertId,
          transaction_code: trxCode,
          type: 'TOPUP',
          amount: nominal,
          status: 'PENDING'
        }

      });


    } catch (error) {

      console.error(
        'Member Deposit Error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Gagal membuat permintaan deposit.'

      });

    }

  }
);


// ==================================================
// ALIAS DEPOSIT
// Untuk frontend yang mungkin memakai /topup
// ==================================================

app.post(
  '/api/transactions/topup',
  verifyToken,
  async (req, res) => {

    req.url = '/api/transactions/deposit';

    const {
      amount,
      payment_method,
      paymentMethod,
      description
    } = req.body || {};

    const nominal = parseFloat(amount);

    const method =
      payment_method ||
      paymentMethod ||
      'MANUAL_TRANSFER';


    try {

      if (
        !nominal ||
        isNaN(nominal) ||
        nominal <= 0
      ) {

        return res.status(400).json({
          success: false,
          message: 'Nominal deposit tidak valid.'
        });

      }


      const trxCode =
        generateTrxCode('DEP');


      const [result] = await pool.execute(
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
          'TOPUP',
          ?,
          'PENDING',
          ?,
          ?
        )
        `,
        [
          req.user.id,
          trxCode,
          nominal,
          method,
          description ||
            'Permintaan deposit member'
        ]
      );


      return res.status(201).json({

        success: true,

        message:
          'Deposit berhasil diajukan dan menunggu persetujuan Admin.',

        data: {
          id: result.insertId,
          transactionId: result.insertId,
          transaction_code: trxCode,
          type: 'TOPUP',
          amount: nominal,
          status: 'PENDING'
        }

      });


    } catch (error) {

      console.error(
        'Topup Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message: 'Gagal membuat permintaan deposit.'
      });

    }

  }
);


// ==================================================
// MEMBER - WITHDRAW
//
// Catatan:
// Withdraw normalnya langsung dibuat PENDING.
// Saldo belum dipotong sampai proses withdrawal
// disetujui/selesai oleh sistem/admin.
//
// Karena frontend Dashboard belum diberikan di sini,
// endpoint dibuat fleksibel.
// ==================================================

app.post(
  '/api/transactions/withdraw',
  verifyToken,
  async (req, res) => {

    const {
      amount,
      payment_method,
      paymentMethod,
      description
    } = req.body || {};

    const nominal = parseFloat(amount);

    const method =
      payment_method ||
      paymentMethod ||
      'MANUAL_TRANSFER';


    try {

      if (
        !nominal ||
        isNaN(nominal) ||
        nominal <= 0
      ) {

        return res.status(400).json({
          success: false,
          message: 'Nominal withdraw tidak valid.'
        });

      }


      if (req.user.role === 'admin') {

        return res.status(403).json({
          success: false,
          message: 'Admin tidak dapat membuat withdraw member.'
        });

      }


      const conn =
        await pool.getConnection();


      try {

        await conn.beginTransaction();


        const [users] =
          await conn.execute(
            `
            SELECT
              id,
              username,
              balance,
              status
            FROM users
            WHERE id = ?
            FOR UPDATE
            `,
            [req.user.id]
          );


        if (users.length === 0) {

          await conn.rollback();

          return res.status(404).json({
            success: false,
            message: 'Akun tidak ditemukan.'
          });

        }


        const user = users[0];


        if (
          user.status &&
          user.status.toLowerCase() !== 'active'
        ) {

          await conn.rollback();

          return res.status(403).json({
            success: false,
            message: 'Akun Anda tidak aktif.'
          });

        }


        const currentBalance =
          parseFloat(user.balance || 0);


        if (currentBalance < nominal) {

          await conn.rollback();

          return res.status(400).json({
            success: false,
            message: 'Saldo tidak mencukupi untuk withdraw.'
          });

        }


        /*
        ------------------------------------------------
        PENTING:
        Saldo belum dipotong ketika status PENDING.

        Dengan begitu:
        Withdraw pending = saldo masih terlihat utuh.
        ------------------------------------------------
        */

        const trxCode =
          generateTrxCode('WD');


        const [result] =
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
              'WITHDRAW',
              ?,
              'PENDING',
              ?,
              ?
            )
            `,
            [
              req.user.id,
              trxCode,
              nominal,
              method,
              description ||
                'Permintaan withdraw member'
            ]
          );


        await conn.commit();


        return res.status(201).json({

          success: true,

          message:
            'Withdraw berhasil diajukan dan menunggu proses Admin.',

          data: {
            id: result.insertId,
            transactionId: result.insertId,
            transaction_code: trxCode,
            type: 'WITHDRAW',
            amount: nominal,
            status: 'PENDING',
            balance: currentBalance
          }

        });


      } catch (error) {

        await conn.rollback();

        throw error;

      } finally {

        conn.release();

      }


    } catch (error) {

      console.error(
        'Member Withdraw Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message: 'Gagal membuat permintaan withdraw.'
      });

    }

  }
);


// ==================================================
// MEMBER - RIWAYAT TRANSAKSI
// ==================================================

app.get(
  '/api/transactions',
  verifyToken,
  async (req, res) => {

    try {

      const [rows] = await pool.execute(
        `
        SELECT
          id,
          transaction_code,
          type,
          amount,
          status,
          payment_method,
          description,
          created_at
        FROM transactions
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 100
        `,
        [req.user.id]
      );


      const data = rows.map(t => ({
        ...t,
        amount: parseFloat(t.amount || 0)
      }));


      return res.json({
        success: true,
        data
      });


    } catch (error) {

      console.error(
        'Member Transactions Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message: 'Gagal mengambil riwayat transaksi.'
      });

    }

  }
);


// ==================================================
// ADMIN LOGIN
// ==================================================

app.post(
  '/api/admin/login',
  async (req, res) => {

    const {
      username,
      password
    } = req.body || {};


    try {

      if (!username || !password) {

        return res.status(400).json({
          success: false,
          message: 'Username dan password wajib diisi!'
        });

      }


      const [rows] = await pool.execute(
        `
        SELECT *
        FROM users
        WHERE username = ?
        AND role = 'admin'
        LIMIT 1
        `,
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


      const isMatch =
        await bcrypt.compare(
          password,
          admin.password_hash
        );


      if (!isMatch) {

        return res.status(401).json({
          success: false,
          message: 'Password admin salah!'
        });

      }


      if (
        admin.status &&
        admin.status.toLowerCase() !== 'active'
      ) {

        return res.status(403).json({
          success: false,
          message: 'Akun Admin sedang tidak aktif.'
        });

      }


      const token = jwt.sign(
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


      return res.json({

        success: true,

        message: 'Login Admin Berhasil!',

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
        message: 'Server error saat login admin.'
      });

    }

  }
);


// ==================================================
// ADMIN SETUP
// ==================================================

app.get(
  '/api/admin/setup',
  async (req, res) => {

    try {

      const [existing] =
        await pool.execute(
          `
          SELECT id
          FROM users
          WHERE username = 'adminbos'
          LIMIT 1
          `
        );


      if (existing.length > 0) {

        return res.json({
          success: false,
          message: 'Akun Admin sudah tersedia.'
        });

      }


      const password =
        'adminboss123';


      const passwordHash =
        await bcrypt.hash(
          password,
          10
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
          'adminbos',
          ?,
          '08123456789',
          'BCA',
          'ADMIN PASTIBOS',
          '00000000',
          9999999.00,
          'active',
          'admin'
        )
        `,
        [passwordHash]
      );


      return res.json({

        success: true,

        message:
          'Berhasil membuat akun Admin pertama!',

        credentials: {
          username: 'adminbos',
          password
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
          'Gagal membuat akun admin: ' +
          error.message
      });

    }

  }
);


// ==================================================
// ADMIN - SEMUA MEMBER
// ==================================================

app.get(
  '/api/admin/users',
  verifyAdmin,
  async (req, res) => {

    try {

      const [rows] = await pool.execute(
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


      const data =
        rows.map(u => ({
          ...u,
          balance: parseFloat(
            u.balance || 0
          )
        }));


      return res.json({

        success: true,

        count: data.length,

        data

      });


    } catch (error) {

      console.error(
        'Get Users Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message: 'Gagal mengambil data pemain.'
      });

    }

  }
);


// ==================================================
// ADMIN - DETAIL MEMBER
// ==================================================

app.get(
  '/api/admin/users/:id',
  verifyAdmin,
  async (req, res) => {

    const userId =
      parseInt(req.params.id, 10);


    if (isNaN(userId)) {

      return res.status(400).json({
        success: false,
        message: 'ID member tidak valid.'
      });

    }


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
          AND role != 'admin'
          LIMIT 1
          `,
          [userId]
        );


      if (rows.length === 0) {

        return res.status(404).json({
          success: false,
          message: 'Member tidak ditemukan.'
        });

      }


      return res.json({
        success: true,
        data: publicUser(rows[0])
      });


    } catch (error) {

      console.error(
        'Get User Detail Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message: 'Gagal mengambil detail member.'
      });

    }

  }
);


// ==================================================
// ADMIN - TAMBAH / KURANGI SALDO MANUAL
//
// Ini mempertahankan fungsi Admin lama.
//
// ADD:
//   saldo bertambah
//   transaction TOPUP SUCCESS
//
// SUBTRACT:
//   saldo berkurang
//   transaction WITHDRAW SUCCESS
// ==================================================

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
        message: 'Data perubahan saldo tidak valid.'
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
          [userId]
        );


      if (rows.length === 0) {

        await conn.rollback();

        return res.status(404).json({
          success: false,
          message: 'Pemain tidak ditemukan.'
        });

      }


      const currentBalance =
        parseFloat(
          rows[0].balance || 0
        );


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
          userId
        ]
      );


      const trxCode =
        generateTrxCode(
          action === 'add'
            ? 'ADMDEP'
            : 'ADMWD'
        );


      /*
      PENTING:
      Gunakan TOPUP, bukan DEPOSIT.
      */

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
          'MANUAL_TRANSFER',
          ?
        )
        `,
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


// ==================================================
// ADMIN - AKTIFKAN / BLOKIR MEMBER
// ==================================================

app.post(
  '/api/admin/users/toggle-status',
  verifyAdmin,
  async (req, res) => {

    const {
      userId,
      status
    } = req.body || {};


    if (
      !userId ||
      !['active', 'suspended'].includes(status)
    ) {

      return res.status(400).json({
        success: false,
        message: 'Status tidak valid!'
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
            userId
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
        message: 'Gagal mengubah status akun.'
      });

    }

  }
);


// ==================================================
// ADMIN - RIWAYAT TRANSAKSI
// ==================================================

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
            u.account_name,
            u.account_number
          FROM transactions t
          JOIN users u
            ON t.user_id = u.id
          ORDER BY
            t.created_at DESC
          LIMIT 100
          `
        );


      const data =
        rows.map(t => ({
          ...t,
          amount:
            parseFloat(t.amount || 0)
        }));


      return res.json({

        success: true,

        count: data.length,

        data

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


// ==================================================
// ADMIN - APPROVE DEPOSIT
//
// ALUR:
// PENDING
//    ↓
// APPROVE
//    ↓
// SUCCESS
//    +
// saldo member bertambah
//
// Semua dilakukan dalam SATU TRANSAKSI DB.
// ==================================================

app.post(
  '/api/admin/transactions/approve',
  verifyAdmin,
  async (req, res) => {

    const transactionId =
      parseInt(
        req.body.transactionId ||
        req.body.id,
        10
      );


    if (isNaN(transactionId)) {

      return res.status(400).json({
        success: false,
        message: 'ID transaksi tidak valid.'
      });

    }


    const conn =
      await pool.getConnection();


    try {

      await conn.beginTransaction();


      // --------------------------------------------
      // LOCK TRANSACTION
      // --------------------------------------------

      const [trxRows] =
        await conn.execute(
          `
          SELECT
            id,
            user_id,
            type,
            amount,
            status,
            transaction_code
          FROM transactions
          WHERE id = ?
          FOR UPDATE
          `,
          [transactionId]
        );


      if (trxRows.length === 0) {

        await conn.rollback();

        return res.status(404).json({
          success: false,
          message: 'Transaksi tidak ditemukan.'
        });

      }


      const trx =
        trxRows[0];


      // --------------------------------------------
      // HARUS TOPUP
      // --------------------------------------------

      if (trx.type !== 'TOPUP') {

        await conn.rollback();

        return res.status(400).json({
          success: false,
          message:
            'Transaksi ini bukan transaksi deposit/topup.'
        });

      }


      // --------------------------------------------
      // HARUS PENDING
      // --------------------------------------------

      if (trx.status !== 'PENDING') {

        await conn.rollback();

        return res.status(400).json({
          success: false,
          message:
            `Transaksi sudah diproses dengan status ${trx.status}.`
        });

      }


      // --------------------------------------------
      // LOCK MEMBER
      // --------------------------------------------

      const [userRows] =
        await conn.execute(
          `
          SELECT
            id,
            username,
            balance,
            status
          FROM users
          WHERE id = ?
          FOR UPDATE
          `,
          [trx.user_id]
        );


      if (userRows.length === 0) {

        await conn.rollback();

        return res.status(404).json({
          success: false,
          message: 'Member transaksi tidak ditemukan.'
        });

      }


      const member =
        userRows[0];


      if (
        member.status &&
        member.status.toLowerCase() !== 'active'
      ) {

        await conn.rollback();

        return res.status(400).json({
          success: false,
          message:
            'Akun member sedang tidak aktif.'
        });

      }


      const currentBalance =
        parseFloat(
          member.balance || 0
        );


      const amount =
        parseFloat(
          trx.amount || 0
        );


      const newBalance =
        currentBalance + amount;


      // --------------------------------------------
      // TAMBAH SALDO
      // --------------------------------------------

      await conn.execute(
        `
        UPDATE users
        SET balance = ?
        WHERE id = ?
        `,
        [
          newBalance,
          member.id
        ]
      );


      // --------------------------------------------
      // TRANSAKSI -> SUCCESS
      // --------------------------------------------

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
          `Deposit ${member.username} berhasil disetujui. Saldo bertambah Rp ${amount.toLocaleString('id-ID')}.`,

        data: {
          transactionId,
          status: 'SUCCESS',
          amount,
          newBalance
        }

      });


    } catch (error) {

      await conn.rollback();

      console.error(
        'Approve Transaction Error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Gagal approve transaksi: ' +
          error.message

      });


    } finally {

      conn.release();

    }

  }
);


// ==================================================
// ADMIN - REJECT DEPOSIT
//
// ALUR:
// PENDING
//    ↓
// REJECT
//    ↓
// FAILED
//    +
// saldo TETAP
// ==================================================

app.post(
  '/api/admin/transactions/reject',
  verifyAdmin,
  async (req, res) => {

    const transactionId =
      parseInt(
        req.body.transactionId ||
        req.body.id,
        10
      );


    const reason =
      req.body.reason ||
      req.body.note ||
      'Deposit ditolak oleh Admin.';


    if (isNaN(transactionId)) {

      return res.status(400).json({
        success: false,
        message: 'ID transaksi tidak valid.'
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


      if (rows.length === 0) {

        await conn.rollback();

        return res.status(404).json({
          success: false,
          message: 'Transaksi tidak ditemukan.'
        });

      }


      const trx =
        rows[0];


      if (trx.type !== 'TOPUP') {

        await conn.rollback();

        return res.status(400).json({
          success: false,
          message:
            'Transaksi ini bukan transaksi deposit/topup.'
        });

      }


      if (trx.status !== 'PENDING') {

        await conn.rollback();

        return res.status(400).json({
          success: false,
          message:
            `Transaksi sudah diproses dengan status ${trx.status}.`
        });

      }


      /*
      ------------------------------------------------
      PENTING:

      REJECT TIDAK menyentuh users.balance.

      Jadi saldo member tetap sama.
      ------------------------------------------------
      */


      await conn.execute(
        `
        UPDATE transactions
        SET
          status = 'FAILED',
          description = ?
        WHERE id = ?
        AND status = 'PENDING'
        `,
        [
          reason,
          transactionId
        ]
      );


      await conn.commit();


      return res.json({

        success: true,

        message:
          'Deposit berhasil ditolak. Saldo member tidak bertambah.',

        data: {
          transactionId,
          status: 'FAILED'
        }

      });


    } catch (error) {

      await conn.rollback();

      console.error(
        'Reject Transaction Error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Gagal reject transaksi: ' +
          error.message

      });


    } finally {

      conn.release();

    }

  }
);


// ==================================================
// ADMIN - APPROVE WITHDRAW
//
// Untuk withdraw PENDING:
// saldo baru dipotong ketika Admin approve.
//
// Jika frontend nanti memakai fungsi withdraw
// dengan approval manual, endpoint ini siap dipakai.
// ==================================================

app.post(
  '/api/admin/transactions/approve-withdraw',
  verifyAdmin,
  async (req, res) => {

    const transactionId =
      parseInt(
        req.body.transactionId ||
        req.body.id,
        10
      );


    if (isNaN(transactionId)) {

      return res.status(400).json({
        success: false,
        message: 'ID transaksi tidak valid.'
      });

    }


    const conn =
      await pool.getConnection();


    try {

      await conn.beginTransaction();


      const [trxRows] =
        await conn.execute(
          `
          SELECT
            id,
            user_id,
            type,
            amount,
            status,
            transaction_code
          FROM transactions
          WHERE id = ?
          FOR UPDATE
          `,
          [transactionId]
        );


      if (trxRows.length === 0) {

        await conn.rollback();

        return res.status(404).json({
          success: false,
          message: 'Transaksi tidak ditemukan.'
        });

      }


      const trx =
        trxRows[0];


      if (trx.type !== 'WITHDRAW') {

        await conn.rollback();

        return res.status(400).json({
          success: false,
          message:
            'Transaksi ini bukan withdraw.'
        });

      }


      if (trx.status !== 'PENDING') {

        await conn.rollback();

        return res.status(400).json({
          success: false,
          message:
            `Transaksi sudah diproses dengan status ${trx.status}.`
        });

      }


      const [userRows] =
        await conn.execute(
          `
          SELECT
            id,
            username,
            balance,
            status
          FROM users
          WHERE id = ?
          FOR UPDATE
          `,
          [trx.user_id]
        );


      if (userRows.length === 0) {

        await conn.rollback();

        return res.status(404).json({
          success: false,
          message: 'Member tidak ditemukan.'
        });

      }


      const member =
        userRows[0];


      const currentBalance =
        parseFloat(
          member.balance || 0
        );


      const amount =
        parseFloat(
          trx.amount || 0
        );


      if (currentBalance < amount) {

        await conn.rollback();

        return res.status(400).json({
          success: false,
          message:
            'Saldo member tidak mencukupi.'
        });

      }


      const newBalance =
        currentBalance - amount;


      await conn.execute(
        `
        UPDATE users
        SET balance = ?
        WHERE id = ?
        `,
        [
          newBalance,
          member.id
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
          `Withdraw ${member.username} berhasil diproses.`,

        data: {
          transactionId,
          status: 'SUCCESS',
          amount,
          newBalance
        }

      });


    } catch (error) {

      await conn.rollback();

      console.error(
        'Approve Withdraw Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Gagal approve withdraw: ' +
          error.message
      });

    } finally {

      conn.release();

    }

  }
);


// ==================================================
// ADMIN - REJECT WITHDRAW
//
// Karena saldo withdraw belum dipotong saat PENDING,
// reject cukup mengubah status menjadi FAILED.
// Saldo tetap.
// ==================================================

app.post(
  '/api/admin/transactions/reject-withdraw',
  verifyAdmin,
  async (req, res) => {

    const transactionId =
      parseInt(
        req.body.transactionId ||
        req.body.id,
        10
      );


    if (isNaN(transactionId)) {

      return res.status(400).json({
        success: false,
        message: 'ID transaksi tidak valid.'
      });

    }


    try {

      const [rows] =
        await pool.execute(
          `
          UPDATE transactions
          SET
            status = 'FAILED',
            description = ?
          WHERE id = ?
          AND type = 'WITHDRAW'
          AND status = 'PENDING'
          `,
          [
            req.body.reason ||
              req.body.note ||
              'Withdraw ditolak oleh Admin.',
            transactionId
          ]
        );


      if (rows.affectedRows === 0) {

        return res.status(400).json({
          success: false,
          message:
            'Withdraw tidak ditemukan atau sudah diproses.'
        });

      }


      return res.json({

        success: true,

        message:
          'Withdraw ditolak. Saldo member tetap.',

        data: {
          transactionId,
          status: 'FAILED'
        }

      });


    } catch (error) {

      console.error(
        'Reject Withdraw Error:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Gagal reject withdraw: ' +
          error.message
      });

    }

  }
);


// ==================================================
// ADMIN - STATISTIK
// ==================================================

app.get(
  '/api/admin/stats',
  verifyAdmin,
  async (req, res) => {

    try {

      const [
        [memberRows],
        [pendingRows],
        [balanceRows]
      ] = await Promise.all([

        pool.execute(
          `
          SELECT COUNT(*) AS total
          FROM users
          WHERE role != 'admin'
          `
        ),

        pool.execute(
          `
          SELECT COUNT(*) AS total
          FROM transactions
          WHERE status = 'PENDING'
          `
        ),

        pool.execute(
          `
          SELECT COALESCE(
            SUM(balance),
            0
          ) AS total
          FROM users
          WHERE role != 'admin'
          `
        )

      ]);


      return res.json({

        success: true,

        data: {
          totalMembers:
            Number(memberRows[0].total || 0),

          pendingTransactions:
            Number(pendingRows[0].total || 0),

          totalBalance:
            parseFloat(
              balanceRows[0].total || 0
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
        message: 'Gagal mengambil statistik.'
      });

    }

  }
);


// ==================================================
// HALAMAN ADMIN
// ==================================================

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


app.get(
  '/api/admin-panel',
  (req, res) => {

    return res.redirect(
      302,
      '/admin.html'
    );

  }
);


// ==================================================
// ERROR HANDLER
// ==================================================

app.use(
  (err, req, res, next) => {

    console.error(
      'Unhandled Server Error:',
      err
    );

    if (res.headersSent) {
      return next(err);
    }

    return res.status(500).json({
      success: false,
      message: 'Internal server error.'
    });

  }
);


// ==================================================
// EXPORT UNTUK VERCEL
// ==================================================

module.exports = app;


// ==================================================
// LOCAL DEVELOPMENT
// ==================================================

if (
  process.env.NODE_ENV !== 'production'
) {

  app.listen(
    PORT,
    () => {

      console.log(
        `PASTIBOS Server berjalan di port ${PORT}`
      );

    }
  );

      }
