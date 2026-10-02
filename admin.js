const API_BASE = 'https://pastibos.vercel.app/api';

let allMembers = [];
let allTransactions = [];
let currentTrxFilter = 'ALL';
let currentPage = 'members';

document.addEventListener('DOMContentLoaded', () => {
  checkAuth();
});

function checkAuth() {
  const token = localStorage.getItem('pastibos_admin_token');
  const adminName = localStorage.getItem('pastibos_admin_username');

  if (token) {
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('app').classList.remove('hidden');
    document.getElementById('adminName').textContent = adminName || 'Admin';
    loadAllData();
  } else {
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('app').classList.add('hidden');
  }
}

async function adminLogin() {
  const user = document.getElementById('loginUser').value.trim();
  const pass = document.getElementById('loginPass').value.trim();
  const msg = document.getElementById('loginMsg');

  if (!user || !pass) {
    msg.textContent = 'Username dan password wajib diisi!';
    return;
  }

  msg.textContent = 'Memverifikasi akun admin...';

  try {
    const res = await fetch(`${API_BASE}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass })
    });
    const result = await res.json();

    if (result.success && result.data && result.data.token) {
      localStorage.setItem('pastibos_admin_token', result.data.token);
      localStorage.setItem('pastibos_admin_username', result.data.username);
      msg.textContent = '';
      showToast('✅ Berhasil login sebagai Admin!');
      checkAuth();
    } else {
      msg.textContent = result.message || 'Login gagal! Periksa username/password.';
    }
  } catch (err) {
    msg.textContent = 'Gagal terhubung ke server backend!';
  }
}

function logout() {
  if (confirm('Keluar dari Admin Control Center?')) {
    localStorage.removeItem('pastibos_admin_token');
    localStorage.removeItem('pastibos_admin_username');
    checkAuth();
  }
}

/* SIDEBAR HANDLERS */
function openSidebar() {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('overlay').classList.add('open');
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('overlay').classList.remove('open');
}

function showPage(pageId) {
  currentPage = pageId;
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const activePage = document.getElementById(`page-${pageId}`);
  if (activePage) activePage.classList.remove('hidden');

  const activeNav = document.querySelector(`.nav-item[data-page="${pageId}"]`);
  if (activeNav) activeNav.classList.add('active');

  closeSidebar();

  if (pageId === 'transactions') {
    renderTransactions();
  }
}

function refreshCurrent() {
  showToast('Memperbarui data...');
  loadAllData();
}

/* LOAD DATA FROM TiDB CLOUD */
async function loadAllData() {
  const token = localStorage.getItem('pastibos_admin_token');
  if (!token) return;

  try {
    const resUsers = await fetch(`${API_BASE}/admin/users`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (resUsers.status === 401 || resUsers.status === 403) {
      logout();
      return;
    }

    const dataUsers = await resUsers.json();
    if (dataUsers.success) {
      allMembers = dataUsers.data || [];
      document.getElementById('memberCount').textContent = `${allMembers.length} Member`;
      renderMembers();
      renderSettings();
    }

    const resTrx = await fetch(`${API_BASE}/admin/transactions`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const dataTrx = await resTrx.json();
    if (dataTrx.success) {
      allTransactions = dataTrx.data || [];
      document.getElementById('trxCount').textContent = `${allTransactions.length} Trx`;
      renderTransactions();
    }
  } catch (err) {
    showToast('Gagal memuat data dari server!');
  }
}

/* 1. RENDER DAFTAR MEMBER */
function renderMembers() {
  const list = document.getElementById('memberList');
  const keyword = (document.getElementById('memberSearch').value || '').toLowerCase().trim();

  const filtered = allMembers.filter(m => 
    (m.username && m.username.toLowerCase().includes(keyword)) ||
    (m.phone && m.phone.toLowerCase().includes(keyword)) ||
    (m.account_number && m.account_number.toLowerCase().includes(keyword))
  );

  if (filtered.length === 0) {
    list.innerHTML = '<div style="text-align: center; padding: 30px; color: var(--text-muted); font-size: 13px;">Tidak ada member ditemukan.</div>';
    return;
  }

  list.innerHTML = filtered.map(m => {
    const isSuspended = m.status === 'suspended';
    return `
      <div class="item-card ${isSuspended ? 'suspended' : ''}">
        <div class="card-top">
          <div>
            <div class="card-user">👤 ${escapeHtml(m.username)}</div>
            <div class="card-phone">📱 ${escapeHtml(m.phone || '-')}</div>
          </div>
          <span class="badge-status ${isSuspended ? 'badge-suspended' : 'badge-active'}">
            ${isSuspended ? 'SUSPENDED' : 'ACTIVE'}
          </span>
        </div>

        <div class="card-grid">
          <div>
            <span>Bank / E-Wallet</span>
            <strong>${escapeHtml(m.bank_name || '-')}</strong>
          </div>
          <div>
            <span>Nomor Rekening</span>
            <strong>${escapeHtml(m.account_number || '-')}</strong>
          </div>
        </div>

        <div class="card-saldo-row">
          <span>SALDO AKUN:</span>
          <span class="card-saldo-val">Rp ${(parseFloat(m.balance) || 0).toLocaleString('id-ID')}</span>
        </div>

        <div class="card-actions">
          <button class="btn-sm btn primary" onclick="quickSaldoPrompt(${m.id}, '${escapeHtml(m.username)}', 'add')">
            ➕ Tambah Saldo
          </button>
          <button class="btn-sm btn danger" onclick="quickSaldoPrompt(${m.id}, '${escapeHtml(m.username)}', 'subtract')">
            ➖ Potong Saldo
          </button>
          <button class="btn-sm btn secondary" onclick="viewDetail(${m.id})">
            👁️ Detail
          </button>
        </div>
      </div>
    `;
  }).join('');
}

/* 2. RENDER SETTING MEMBER */
function renderSettings() {
  const list = document.getElementById('settingList');
  const keyword = (document.getElementById('settingSearch').value || '').toLowerCase().trim();

  const filtered = allMembers.filter(m => 
    (m.username && m.username.toLowerCase().includes(keyword)) ||
    (m.account_number && m.account_number.toLowerCase().includes(keyword))
  );

  if (filtered.length === 0) {
    list.innerHTML = '<div style="text-align: center; padding: 30px; color: var(--text-muted); font-size: 13px;">Tidak ada member ditemukan.</div>';
    return;
  }

  list.innerHTML = filtered.map(m => `
    <div class="item-card">
      <div class="card-top">
        <div>
          <div class="card-user">⚙️ ${escapeHtml(m.username)}</div>
          <div class="card-phone">${escapeHtml(m.bank_name || '-')} • ${escapeHtml(m.account_number || '-')}</div>
        </div>
        <button class="btn-sm btn primary" onclick="openEditModal(${m.id})">
          Ubah Data
        </button>
      </div>
    </div>
  `).join('');
}

/* 3. RENDER TRANSAKSI */
function filterTrx(type, btn) {
  currentTrxFilter = type;
  document.querySelectorAll('.filter').forEach(f => f.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderTransactions();
}

function renderTransactions() {
  const list = document.getElementById('trxList');

  let filtered = allTransactions;
  if (currentTrxFilter === 'TOPUP') {
    filtered = allTransactions.filter(t => t.type === 'TOPUP');
  } else if (currentTrxFilter === 'WITHDRAW') {
    filtered = allTransactions.filter(t => t.type === 'WITHDRAW');
  } else if (currentTrxFilter === 'PENDING') {
    filtered = allTransactions.filter(t => t.status === 'PENDING');
  }

  if (filtered.length === 0) {
    list.innerHTML = '<div style="text-align: center; padding: 30px; color: var(--text-muted); font-size: 13px;">Tidak ada transaksi.</div>';
    return;
  }

  list.innerHTML = filtered.map(t => {
    const isTopup = t.type === 'TOPUP';
    return `
      <div class="item-card">
        <div class="card-top">
          <div>
            <div class="card-user">${isTopup ? '📥 DEPOSIT' : '📤 WITHDRAW'} - ${escapeHtml(t.username || '-')}</div>
            <div class="card-phone">${formatDate(t.created_at)} • ${escapeHtml(t.transaction_code)}</div>
          </div>
          <strong style="color: ${isTopup ? 'var(--success)' : '#f87171'}; font-size: 15px;">
            ${isTopup ? '+' : '-'} Rp ${(parseFloat(t.amount) || 0).toLocaleString('id-ID')}
          </strong>
        </div>
        <div style="font-size: 11.5px; color: var(--text-muted); display: flex; justify-content: space-between;">
          <span>Metode: ${escapeHtml(t.payment_method)}</span>
          <span style="font-weight: 700; color: ${t.status === 'SUCCESS' ? 'var(--success)' : '#f59e0b'};">${t.status}</span>
        </div>
      </div>
    `;
  }).join('');
}

/* DETAIL MEMBER */
function viewDetail(userId) {
  const m = allMembers.find(u => u.id === userId);
  if (!m) return;

  const body = document.getElementById('detailBody');
  body.innerHTML = `
    <div class="detail-row"><span>ID Member</span><strong>#${m.id}</strong></div>
    <div class="detail-row"><span>Username</span><strong>${escapeHtml(m.username)}</strong></div>
    <div class="detail-row"><span>Nomor HP</span><strong>${escapeHtml(m.phone || '-')}</strong></div>
    <div class="detail-row"><span>Bank / E-Wallet</span><strong>${escapeHtml(m.bank_name || '-')}</strong></div>
    <div class="detail-row"><span>Nama Pemilik</span><strong>${escapeHtml(m.account_name || '-')}</strong></div>
    <div class="detail-row"><span>Nomor Rekening</span><strong>${escapeHtml(m.account_number || '-')}</strong></div>
    <div class="detail-row"><span>Saldo Sekarang</span><strong style="color: var(--primary);">Rp ${(parseFloat(m.balance) || 0).toLocaleString('id-ID')}</strong></div>
    <div class="detail-row"><span>Status Akun</span><strong>${(m.status || 'ACTIVE').toUpperCase()}</strong></div>
    <div class="detail-row"><span>Tanggal Daftar</span><strong>${formatDate(m.created_at)}</strong></div>
  `;

  openModal('detailModal');
}

/* EDIT MEMBER */
function openEditModal(userId) {
  const m = allMembers.find(u => u.id === userId);
  if (!m) return;

  document.getElementById('editId').value = m.id;
  document.getElementById('editUsername').value = m.username;
  document.getElementById('editPhone').value = m.phone || '';
  document.getElementById('editBank').value = m.bank_name || '';
  document.getElementById('editAccountName').value = m.account_name || '';
  document.getElementById('editAccountNumber').value = m.account_number || '';
  document.getElementById('editStatus').value = m.status || 'active';
  document.getElementById('editMsg').textContent = '';

  openModal('editModal');
}

async function saveMember() {
  const token = localStorage.getItem('pastibos_admin_token');
  const id = document.getElementById('editId').value;
  const status = document.getElementById('editStatus').value;
  const msg = document.getElementById('editMsg');

  try {
    await fetch(`${API_BASE}/admin/users/toggle-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({ userId: id, status: status })
    });

    showToast('✅ Status akun berhasil diperbarui!');
    closeModal('editModal');
    loadAllData();
  } catch (err) {
    msg.textContent = 'Gagal menyimpan perubahan!';
  }
}

/* QUICK SALDO ADJUST */
async function quickSaldoPrompt(userId, username, action) {
  const actionText = action === 'add' ? 'TAMBAH SALDO' : 'POTONG SALDO';
  const input = prompt(`Masukkan nominal rupiah untuk ${actionText} member: ${username}\nContoh: 50000`, '50000');
  
  if (!input) return;
  const amount = parseFloat(input);
  if (isNaN(amount) || amount <= 0) {
    alert('Nominal harus berupa angka lebih dari 0!');
    return;
  }

  const token = localStorage.getItem('pastibos_admin_token');
  try {
    const res = await fetch(`${API_BASE}/admin/users/adjust-balance`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        userId: userId,
        amount: amount,
        action: action,
        note: action === 'add' ? 'Tambah saldo oleh Admin' : 'Potong saldo oleh Admin'
      })
    });

    const data = await res.json();
    if (data.success) {
      showToast(`✅ ${data.message}`);
      loadAllData();
    } else {
      showToast(`❌ ${data.message}`);
    }
  } catch (err) {
    showToast('Gagal memproses saldo ke server.');
  }
}

/* MODAL HELPERS */
function openModal(id) {
  const m = document.getElementById(id);
  if (m) m.classList.remove('hidden');
}

function closeModal(id) {
  const m = document.getElementById(id);
  if (m) m.classList.add('hidden');
}

/* UTILS */
function showToast(text) {
  const t = document.getElementById('toast');
  t.textContent = text;
  t.style.display = 'block';
  setTimeout(() => { t.style.display = 'none'; }, 3500);
}

function formatDate(dStr) {
  if (!dStr) return '-';
  const d = new Date(dStr);
  return d.toLocaleDateString('id-ID', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, m => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));
}