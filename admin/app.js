const API = location.origin;
function tok() { return localStorage.getItem('ADMIN_TOKEN') || ''; }
function hdr() { return { 'Authorization':'Bearer ' + tok(), 'Content-Type':'application/json' }; }

let page=1, limit=25, selected=null;

/* ---------- helpers ---------- */
function fmtDate(s){ if(!s) return '—'; const d=new Date(s); return d.toLocaleString(); }
function statusBadge(s){
  const cls = s==='disabled' ? 'disabled' : (s==='retired' ? 'retired' : 'active');
  const dot = s==='disabled' ? 'red' : (s==='retired' ? 'amber' : 'green');
  return `<span class="badge ${cls}"><span class="dot ${dot}"></span>${s||'active'}</span>`;
}
function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function renderKV(elId, rows){
  const el = document.getElementById(elId);
  el.innerHTML = rows.map(([k,v]) => `
    <div>${escapeHtml(k)}</div>
    <div>${v ?? '—'}</div>
  `).join('');
}
function bindTabs(){
  document.querySelectorAll('.tab').forEach(btn=>{
    btn.addEventListener('click', (e)=>{
      e.preventDefault();
      document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
      document.querySelectorAll('.tabpane').forEach(p=>p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-'+btn.dataset.tab).classList.add('active');
    });
  });
}

/* ---------- auth / shell ---------- */
async function ensureLogin(){
  const has = !!tok();
  const login  = document.getElementById('login');
  const app    = document.getElementById('app');
  const topbar = document.getElementById('topbar');
  login.style.display  = has ? 'none'  : 'block';
  app.style.display    = has ? 'block' : 'none';
  topbar.style.display = has ? 'block' : 'none';
}

document.getElementById('loginBtn').onclick=()=>{
  const v = document.getElementById('token').value.trim();
  if(!v){ alert('Enter token'); return; }
  localStorage.setItem('ADMIN_TOKEN', v);
  ensureLogin().then(load);
};
document.getElementById('logout').onclick=()=>{
  localStorage.removeItem('ADMIN_TOKEN'); ensureLogin();
};

/* ---------- grid load ---------- */
async function load(){
  const q = document.getElementById('q').value.trim();
  const status = document.getElementById('status').value;
  const url = new URL(API + '/admin/api/devices');
  url.searchParams.set('page', page);
  url.searchParams.set('limit', limit);
  if(q) url.searchParams.set('q', q);
  if(status) url.searchParams.set('status', status);

  const r = await fetch(url, { headers: hdr() });
  if(r.status===401){ alert('Unauthorized — set a valid ADMIN_TOKEN'); return; }
  const json = await r.json();

  document.getElementById('count').textContent = `Total: ${json.total}`;
  document.getElementById('pagerInfo').textContent = `Page ${json.page} / ${Math.ceil((json.total||0)/json.limit||1)}`;

  const tb = document.querySelector('#grid tbody');
  tb.innerHTML='';
  json.items.forEach(it=>{
    const tr = document.createElement('tr');
    tr.className = 'clickable';
    tr.dataset.id = it.deviceId;
    tr.innerHTML = `
      <td><code>${it.deviceId}</code></td>
      <td>${escapeHtml(it.hostname||'—')}</td>
      <td>${escapeHtml(it.username||'—')}</td>
      <td>${escapeHtml([it.osName,it.osVersion].filter(Boolean).join(' '))}</td>
      <td>${fmtDate(it.lastSeenAt)||fmtDate(it.updatedAt)||'—'}</td>
      <td>${statusBadge(it.status||'active')}</td>`;
    tr.onclick = ()=>{
      document.querySelectorAll('#grid tbody tr.selected').forEach(x=>x.classList.remove('selected'));
      tr.classList.add('selected');
      select(it.deviceId);
    };
    tb.appendChild(tr);
  });

  if(selected){
    const row = tb.querySelector(`tr[data-id="${selected}"]`);
    if(row) row.classList.add('selected');
  }
}

/* ---------- detail load ---------- */
async function select(id){
  selected=id;

  const d = await (await fetch(API+'/admin/api/devices/'+id, { headers: hdr() })).json();
  if(!d.ok) return alert(d.error||'load error');
  const x = d.device;

  document.getElementById('devTitle').textContent = x.hostname || 'Details';

  renderKV('ovDevice', [
    ['Device Name', escapeHtml(x.hostname||'—')],
    ['Device ID', `<code>${x.deviceId}</code>`],
    ['User', escapeHtml(x.username||'—')],
    ['Architecture', escapeHtml(x.arch||'—')],
  ]);
  renderKV('ovConfig', [
    ['App Version', escapeHtml(x.appVersion||'—')],
    ['Tauri Version', escapeHtml(x.tauriVersion||'—')],
    ['Status', statusBadge(x.status||'active')],
    ['First seen', fmtDate(x.firstSeenAt)],
    ['Last online', fmtDate(x.lastSeenAt||x.updatedAt)],
    ['IP (last)', escapeHtml(x.ipLast||'—')],
  ]);
  renderKV('ovOs', [
    ['Platform', escapeHtml(x.osName||'—')],
    ['OS Version', escapeHtml(x.osVersion||'—')],
  ]);

  document.getElementById('setStatus').value = x.status || 'active';

  const ev = await (await fetch(API+'/admin/api/devices/'+id+'/events?limit=50', { headers: hdr() })).json();
  const evEl = document.getElementById('eventsList');
  evEl.innerHTML =
    ev.ok && ev.events.length
      ? ev.events.map(e=>`
          <div class="item">
            <div class="when">${fmtDate(e.createdAt)}</div>
            <div class="body">
              <strong>${escapeHtml(e.eventType)}</strong>
              <div><code>${escapeHtml(JSON.stringify(e.payload))}</code></div>
            </div>
          </div>`).join('')
      : '<div class="muted">No events.</div>';

  const nt = await (await fetch(API+'/admin/api/devices/'+id+'/notes', { headers: hdr() })).json();
  const ntEl = document.getElementById('notesList');
  ntEl.innerHTML =
    nt.ok && nt.notes.length
      ? nt.notes.map(n=>`
          <div class="note">
            <div class="meta">${fmtDate(n.createdAt)} • <strong>${escapeHtml(n.createdBy)}</strong></div>
            <div>${escapeHtml(n.note)}</div>
          </div>`).join('')
      : '<div class="muted">No notes.</div>';
}

/* ---------- actions ---------- */
document.getElementById('addNote').onclick = async ()=>{
  if(!selected) return alert('Select a device first');
  const note = document.getElementById('noteText').value.trim();
  const by   = document.getElementById('noteBy').value.trim() || 'admin';
  if(!note) return;
  const r = await fetch(API+'/admin/api/devices/'+selected+'/notes', {
    method:'POST', headers: hdr(), body: JSON.stringify({ note, createdBy: by })
  });
  const j = await r.json(); if(!j.ok) return alert(j.error||'error');
  document.getElementById('noteText').value='';
  select(selected);
};

document.getElementById('applyStatus').onclick = async ()=>{
  if(!selected) return alert('Select a device first');
  const status = document.getElementById('setStatus').value;
  const r = await fetch(API+'/admin/api/devices/'+selected+'/status', {
    method:'POST', headers: hdr(), body: JSON.stringify({ status })
  });
  const j = await r.json(); if(!j.ok) return alert(j.error||'error');
  load(); select(selected);
};

document.getElementById('refresh').onclick=()=>{ page=1; load(); };
document.getElementById('prev').onclick=()=>{ if(page>1){ page--; load(); } };
document.getElementById('next').onclick=()=>{ page++; load(); };

/* init */
bindTabs();
ensureLogin().then(load);
