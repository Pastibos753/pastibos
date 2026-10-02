
const API_BASE = 'https://pastibos.vercel.app';
let token = localStorage.getItem('pastibos_admin_token') || '';
let adminUser = localStorage.getItem('pastibos_admin_name') || '';
let members = [], transactions = [], trxFilter = 'ALL';

document.addEventListener('DOMContentLoaded',()=>{ if(token){showApp();} });

function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function money(v){return 'Rp '+(Number(v)||0).toLocaleString('id-ID')}
function date(v){return v?new Date(v).toLocaleString('id-ID',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}):'-'}
function toast(msg){const e=document.getElementById('toast');e.className='toast';e.textContent=msg;setTimeout(()=>e.className='',2600)}
function headers(){return {'Authorization':`Bearer ${token}`,'Content-Type':'application/json'}}
function openSidebar(){document.getElementById('sidebar').classList.add('open');document.getElementById('overlay').classList.add('show')}
function closeSidebar(){document.getElementById('sidebar').classList.remove('open');document.getElementById('overlay').classList.remove('show')}

async function adminLogin(){
 const username=document.getElementById('loginUser').value.trim(),password=document.getElementById('loginPass').value;
 const msg=document.getElementById('loginMsg'); msg.textContent='Memproses...';
 try{
  const r=await fetch(`${API_BASE}/api/admin/login`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
  const d=await r.json(); if(!d.success) throw new Error(d.message||'Login gagal');
  token=d.data.token;adminUser=d.data.username||username;localStorage.setItem('pastibos_admin_token',token);localStorage.setItem('pastibos_admin_name',adminUser);showApp();
 }catch(e){msg.textContent=e.message}
}
function showApp(){document.getElementById('loginScreen').classList.add('hidden');document.getElementById('app').classList.remove('hidden');document.getElementById('adminName').textContent=adminUser||'-';loadMembers();loadTransactions()}
function logout(){localStorage.removeItem('pastibos_admin_token');localStorage.removeItem('pastibos_admin_name');token='';location.reload()}

async function api(path,opt={}){const r=await fetch(API_BASE+path,{...opt,headers:{...headers(),...(opt.headers||{})}});const d=await r.json();if(r.status===401||r.status===403){logout();throw new Error('Sesi Admin berakhir.')}if(!d.success)throw new Error(d.message||'Gagal memuat data');return d}

async function loadMembers(){
 const box=document.getElementById('memberList');box.innerHTML='<div class="member-card">Memuat member...</div>';
 try{const d=await api('/api/admin/users');members=d.data||[];document.getElementById('memberCount').textContent=`${members.length} Member`;renderMembers();renderSettings()}
 catch(e){box.innerHTML=`<div class="member-card">${esc(e.message)}</div>`}
}
function memberCard(u,setting=false){
 return `<div class="member-card">
  <div class="member-top"><div><div class="username">${esc(u.username)}</div><div class="sub">${esc(u.phone||'-')} · ID ${u.id}</div></div><div class="balance">${money(u.balance)}</div></div>
  <div class="badges"><span class="badge ${u.status==='active'?'active':'suspended'}">${esc((u.status||'').toUpperCase())}</span><span class="badge">${esc(u.bank_name||'Belum ada bank')}</span><span class="badge">${date(u.created_at)}</span></div>
  <div class="actions">${setting?`<button class="gold" onclick="openEdit(${u.id})">⚙️ SETTING</button>`:`<button onclick="openDetail(${u.id})">👁️ DETAIL</button><button class="gold" onclick="openEdit(${u.id})">⚙️ SETTING</button>`}</div>
 </div>`
}
function renderMembers(){const q=(document.getElementById('memberSearch')?.value||'').toLowerCase();const data=members.filter(u=>`${u.username} ${u.phone}`.toLowerCase().includes(q));document.getElementById('memberList').innerHTML=data.length?data.map(u=>memberCard(u)).join(''):'<div class="member-card">Belum ada member.</div>'}
function renderSettings(){const q=(document.getElementById('settingSearch')?.value||'').toLowerCase();const data=members.filter(u=>`${u.username} ${u.phone}`.toLowerCase().includes(q));document.getElementById('settingList').innerHTML=data.length?data.map(u=>memberCard(u,true)).join(''):'<div class="member-card">Belum ada member.</div>'}

async function openDetail(id){
 const u=members.find(x=>x.id===id);if(!u)return;
 const body=document.getElementById('detailBody');
 body.innerHTML=`<div class="detail-grid">
  ${[['Username',u.username],['ID',u.id],['Nomor HP',u.phone],['Bank / E-Wallet',u.bank_name],['Nama Pemilik',u.account_name],['Nomor Rekening',u.account_number],['Referral',u.referral_code||'-'],['Status',(u.status||'').toUpperCase()],['Saldo',money(u.balance)],['Terdaftar',date(u.created_at)]].map(x=>`<div class="detail-box"><small>${esc(x[0])}</small><b>${esc(x[1])}</b></div>`).join('')}
 </div><div class="section-label">RIWAYAT TRANSAKSI</div><div id="detailTrx">Memuat...</div>`;
 document.getElementById('detailModal').classList.remove('hidden');
 try{const d=await api(`/api/admin/users/${id}/details`);const rows=d.data?.transactions||d.transactions||[];document.getElementById('detailTrx').innerHTML=rows.length?rows.map(t=>`<div class="trx-card" style="margin-bottom:8px"><div><b class="${t.type==='TOPUP'?'topup':'withdraw'}">${t.type==='TOPUP'?'+ DEPOSIT':'- WITHDRAW'}</b><div class="sub">${esc(t.transaction_code)} · ${date(t.created_at)}</div></div><div class="trx-amount">${money(t.amount)}</div><div class="trx-meta"><span class="status ${t.status==='SUCCESS'?'status-success':t.status==='FAILED'?'status-failed':'status-pending'}">${esc(t.status)}</span><span>${esc(t.payment_method||'-')}</span></div></div>`).join(''):'<div class="member-card">Belum ada transaksi.</div>'}
 catch(e){document.getElementById('detailTrx').innerHTML=`<div class="member-card">${esc(e.message)}</div>`}
}
function closeModal(id){document.getElementById(id).classList.add('hidden')}

function openEdit(id){const u=members.find(x=>x.id===id);if(!u)return;document.getElementById('editId').value=u.id;document.getElementById('editUsername').value=u.username||'';document.getElementById('editPhone').value=u.phone||'';document.getElementById('editBank').value=u.bank_name||'';document.getElementById('editAccountName').value=u.account_name||'';document.getElementById('editAccountNumber').value=u.account_number||'';document.getElementById('editStatus').value=u.status||'active';document.getElementById('editMsg').textContent='';document.getElementById('editModal').classList.remove('hidden')}
async function saveMember(){
 const userId=Number(document.getElementById('editId').value);
 const payload={userId,phone:document.getElementById('editPhone').value.trim(),bank_name:document.getElementById('editBank').value.trim(),account_name:document.getElementById('editAccountName').value.trim(),account_number:document.getElementById('editAccountNumber').value.trim(),status:document.getElementById('editStatus').value};
 const msg=document.getElementById('editMsg');msg.textContent='Menyimpan...';
 try{await api('/api/admin/users/update',{method:'POST',body:JSON.stringify(payload)});toast('Data member berhasil diperbarui');closeModal('editModal');await loadMembers()}
 catch(e){msg.textContent=e.message}
}

async function loadTransactions(){
 const box=document.getElementById('trxList');box.innerHTML='<div class="trx-card">Memuat transaksi...</div>';
 try{const d=await api('/api/admin/transactions');transactions=d.data||[];document.getElementById('trxCount').textContent=`${transactions.length} transaksi`;renderTransactions()}
 catch(e){box.innerHTML=`<div class="trx-card">${esc(e.message)}</div>`}
}
function renderTransactions(){
 const data=transactions.filter(t=>trxFilter==='ALL'||t.type===trxFilter||t.status===trxFilter);
 document.getElementById('trxList').innerHTML=data.length?data.map(t=>`<div class="trx-card">
 <div><div class="trx-type ${t.type==='TOPUP'?'topup':'withdraw'}">${t.type==='TOPUP'?'+ DEPOSIT':'- WITHDRAW'} · ${esc(t.username)}</div><div class="sub">${esc(t.transaction_code)} · ${date(t.created_at)}</div></div>
 <div class="trx-amount">${money(t.amount)}</div>
 <div class="trx-meta"><span class="status ${t.status==='SUCCESS'?'status-success':t.status==='FAILED'?'status-failed':'status-pending'}">${esc(t.status)}</span><span>${esc(t.payment_method||'-')}</span>${t.status==='PENDING'?`<span class="actions"><button class="green" onclick="approveTrx(${t.id})">✅ PROSES</button><button class="red" onclick="rejectTrx(${t.id})">❌ REJECT</button></span>`:''}</div>
 </div>`).join(''):'<div class="trx-card">Tidak ada transaksi.</div>'
}
function filterTrx(v,el){trxFilter=v;document.querySelectorAll('.filter').forEach(x=>x.classList.remove('active'));el.classList.add('active');renderTransactions()}
async function approveTrx(id){if(!confirm('Proses transaksi ini?'))return;try{await api('/api/admin/transactions/approve',{method:'POST',body:JSON.stringify({transactionId:id})});toast('Transaksi berhasil diproses');await loadTransactions()}catch(e){toast(e.message)}}
async function rejectTrx(id){if(!confirm('Tolak transaksi ini?'))return;try{await api('/api/admin/transactions/reject',{method:'POST',body:JSON.stringify({transactionId:id})});toast('Transaksi ditolak');await loadTransactions()}catch(e){toast(e.message)}}

function showPage(page){
 document.querySelectorAll('.page').forEach(x=>x.classList.add('hidden'));document.getElementById(`page-${page}`).classList.remove('hidden');
 document.querySelectorAll('.nav-item').forEach(x=>x.classList.toggle('active',x.dataset.page===page));closeSidebar();
 if(page==='members')loadMembers();if(page==='transactions')loadTransactions();
}
function refreshCurrent(){const active=document.querySelector('.nav-item.active')?.dataset.page||'members';if(active==='members'||active==='settings')loadMembers();else loadTransactions()}
