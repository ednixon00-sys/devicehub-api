const API = location.origin;
function tok() { return localStorage.getItem('ADMIN_TOKEN') || ''; }
function hdr() { return { 'Authorization':'Bearer ' + tok(), 'Content-Type':'application/json' }; }

let page=1, limit=25, selected=null;

function fmtDate(s){ if(!s) return '—'; const d=new Date(s); return d.toLocaleString(); }
function statusPill(s){
  const cls = s==='disabled' ? 'status-disabled' : (s==='retired' ? 'status-retired' : 'status-active');
  return '<span class="pill '+cls+'">'+s+'</span>';
}

async function ensureLogin(){
  const has = !!tok();
  document.getElementById('login').style.display = has?'none':'block';
  document.getElementById('app').style.display   = has?'block':'none';
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
  document.getElementById('pagerInfo').textContent = `Page ${json.page} / ${Math.ceil(json.total/json.limit||1)}`;

  const tb = document.querySelector('#grid tbody');
  tb.innerHTML='';
  json.items.forEach(it=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${it.deviceId}</code></td>
      <td>${it.hostname||'—'}</td>
      <td>${it.username||'—'}</td>
      <td>${it.osName||''} ${it.osVersion||''}</td>
      <td>${fmtDate(it.lastSeenAt)||fmtDate(it.updatedAt)||'—'}</td>
      <td>${statusPill(it.status||'active')}</td>`;
    tr.onclick = ()=> select(it.deviceId);
    tb.appendChild(tr);
  });
}

async function select(id){
  selected=id;
  // details
  const d = await (await fetch(API+'/admin/api/devices/'+id, { headers: hdr() })).json();
  if(!d.ok) return alert(d.error||'load error');
  const x = d.device;
  document.getElementById('dBody').innerHTML = `
    <div><strong>Device:</strong> <code>${x.deviceId}</code></div>
    <div class="muted">${x.osName||''} ${x.osVersion||''} • ${x.arch||''}</div>
    <div class="muted">Host: ${x.hostname||'—'} • User: ${x.username||'—'}</div>
    <div class="muted">IP: ${x.ipLast||'—'} • Status: ${x.status||'active'}</div>
    <div class="muted">First: ${fmtDate(x.firstSeenAt)} • Last: ${fmtDate(x.lastSeenAt)}</div>
  `;
  document.getElementById('setStatus').value = x.status || 'active';

  // events
  const ev = await (await fetch(API+'/admin/api/devices/'+id+'/events?limit=50', { headers: hdr() })).json();
  document.getElementById('events').innerHTML =
    ev.ok && ev.events.length
      ? ev.events.map(e=>`<div>• <span class="muted">${fmtDate(e.createdAt)}</span> <strong>${e.eventType}</strong> — <code>${JSON.stringify(e.payload)}</code></div>`).join('')
      : '<span class="muted">No events.</span>';

  // notes
  const nt = await (await fetch(API+'/admin/api/devices/'+id+'/notes', { headers: hdr() })).json();
  document.getElementById('notes').innerHTML =
    nt.ok && nt.notes.length
      ? nt.notes.map(n=>`<div>• <span class="muted">${fmtDate(n.createdAt)}</span> <strong>${n.createdBy}:</strong> ${n.note}</div>`).join('')
      : '<span class="muted">No notes.</span>';
}

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

ensureLogin().then(load);
