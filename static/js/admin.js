/* ============ AURA OSINT HUB — admin js ============ */
const $  = (s, el=document) => el.querySelector(s);
const $$ = (s, el=document) => [...el.querySelectorAll(s)];

function toast(msg, ok=true){
  let wrap = $('#toast');
  if(!wrap){ wrap=document.createElement('div'); wrap.id='toast'; document.body.appendChild(wrap); }
  const t=document.createElement('div');
  t.className='toast '+(ok?'ok':'err'); t.textContent=msg;
  wrap.appendChild(t);
  setTimeout(()=>{t.style.opacity='0';t.style.transition='opacity .4s';setTimeout(()=>t.remove(),450)},2600);
}

async function post(url, data){
  try{
    const body = data instanceof FormData ? data : Object.entries(data||{}).reduce((fd,[k,v])=>{fd.append(k,v);return fd}, new FormData());
    const r = await fetch(url,{method:'POST',body});
    const j = await r.json().catch(()=>({ok:r.ok}));
    if(!r.ok || j.ok===false) throw new Error(j.error||'request failed');
    return j;
  }catch(e){ toast('Error: '+e.message,false); throw e; }
}

/* ---------- sidebar (mobile) ---------- */
document.addEventListener('click', e=>{
  if(e.target.closest('#menuBtn')){ $('.sidebar').classList.add('open'); $('#overlay').classList.add('show'); }
  if(e.target.id==='overlay' || e.target.closest('.side-nav a')){ $('.sidebar')?.classList.remove('open'); $('#overlay')?.classList.remove('show'); }
});

/* ---------- flash close ---------- */
document.addEventListener('click',e=>{
  if(e.target.classList.contains('x')) e.target.closest('.flash').remove();
  /* switches */
  if(e.target.classList.contains('sw')||e.target.closest('.sw')){
    const sw = e.target.classList.contains('sw')? e.target : e.target.closest('.sw');
    const url = sw.dataset.url;
    if(!url) return;
    post(url,{_t:1}).then(j=>{
      if(typeof j.enabled==='boolean') sw.classList.toggle('on',j.enabled); else sw.classList.toggle('on');
    });
  }
  /* modals */
  if(e.target.classList.contains('modal-bg') && e.target.classList.contains('show')) closeModal(e.target);
  if(e.target.closest('[data-close-modal]')) closeModal(e.target.closest('.modal-bg'));
});

function openModal(sel){ const m=$(sel); m.classList.add('show'); document.body.style.overflow='hidden'; }
function closeModal(m){ m?.classList.remove('show'); document.body.style.overflow=''; }
function openModalId(id){ openModal('#'+id); }
window.openModalId=openModalId; window.closeModal=closeModal;

/* auto page-open modal via hash e.g. #newKey */
if(location.hash.startsWith('#m-')){ setTimeout(()=>openModalId(location.hash.slice(3)),60); }

/* ---------- copy (tap-to-copy with fallback + flash) ---------- */
document.addEventListener('click', e=>{
  const c=e.target.closest('[data-copy]');
  if(!c) return;
  const done=()=>{
    toast('Copied: '+c.dataset.copy);
    c.classList.add('copied');
    setTimeout(()=>c.classList.remove('copied'),900);
  };
  const cv = navigator.clipboard && navigator.clipboard.writeText
    ? navigator.clipboard.writeText(c.dataset.copy) : Promise.reject();
  cv.then(done).catch(()=>{
    const ta=document.createElement('textarea');
    ta.value=c.dataset.copy; ta.style.position='fixed'; ta.style.opacity='0';
    document.body.appendChild(ta); ta.select();
    try{ document.execCommand('copy'); done(); }
    catch(_){ toast('Copy failed',false); }
    ta.remove();
  });
});

/* =================================================================
   KEYS PAGE
================================================================= */
/* custom key toggle */
$$('.switch-input').forEach(inp=>{
  inp.addEventListener('change',()=>{
    const target = $(inp.dataset.target);
    if(target){ target.style.display = inp.checked?'block':'none'; target.querySelector('input')?.focus(); }
  });
});
/* pre-state on load */
$$('.switch-input:checked').forEach(i=>{const t=$(i.dataset.target); if(t)t.style.display='block';});

/* access mode seg */
$$('.seg.mode-access button').forEach(b=>{
  b.addEventListener('click',()=>{
    $$('.seg.mode-access button').forEach(x=>x.classList.remove('active')); b.classList.add('active');
    const form=b.closest('form');
    $('.row-single',form).style.display=b.dataset.v==='single'?'block':'none';
    $('.row-multiple',form).style.display=b.dataset.v==='multiple'?'block':'none';
    form.querySelector('[name=access_mode]').value=b.dataset.v;
  });
});

/* usage mode seg */
$$('.seg.mode-usage button').forEach(b=>{
  b.addEventListener('click',()=>{
    $$('.seg.mode-usage button').forEach(x=>x.classList.remove('active')); b.classList.add('active');
    const form=b.closest('form');
    form.querySelector('[name=usage_mode]').value=b.dataset.v;
    const box=$('.limits-rl',form), box2=$('.limits-cap',form);
    if(box) box.style.display = b.dataset.v==='rate_limited'?'block':'none';
    if(box2) box2.style.display = b.dataset.v==='fixed_cap'?'block':'none';
    const hint=$('.usage-hint',form);
    if(hint){
      const hints={unlimited:'No caps at all — no daily limit, no per-minute limit, no total cap.',
                   rate_limited:'Follows the daily / per-minute limits below (optional total cap too).',
                   fixed_cap:'Fixed total-hit number. The key auto-disables the moment it is reached.'};
      hint.textContent=hints[b.dataset.v];
    }
  });
});

/* validity select -> custom date */
$$('select[name=validity]').forEach(sel=>{
  sel.addEventListener('change',()=>{
    const form=sel.closest('form');
    $('.row-custom-date',form).style.display = sel.value==='custom'?'block':'none';
  });
});

/* open create modal */
document.addEventListener('click', e => {
  const btn = e.target.closest('#newKeyBtn');
  if(!btn) return;
  e.preventDefault();
  const m = document.getElementById('m-new');
  if(!m) return;
  const form = m.querySelector('form');
  if(form) form.reset();
  $$('.seg.mode-access button[data-v=all]', m).forEach(x => x.click());
  $$('.seg.mode-usage button[data-v=unlimited]', m).forEach(x => x.click());
  $$('.row-custom-date', m).forEach(x => x.style.display = 'none');
  $$('.switch-input', m).forEach(i => {
    i.checked = false;
    i.dispatchEvent(new Event('change'));
  });
  openModal('#m-new');
});

/* open edit modal (delegate) */
document.addEventListener('click',e=>{
  const t=e.target.closest('[data-edit-key]');
  if(!t) return;
  const d=t.dataset;
  const m=$('#m-edit'); if(!m) return;
  const form=m.querySelector('form');
  form.action=d.url;
  form['client'].value=d.client||'';
  const kv=$('#editKeyView'); if(kv) kv.value=d.key||'';
  form['note'].value=d.note||'';
  form['style_developer'].value=d.dev||'';
  form['style_template'].value=d.tpl||'';
  form['daily_limit'].value=d.daily||0;
  form['per_min_limit'].value=d.permin||0;
  form['total_cap'].value=d.cap||0;
  /* access */
  const allowed=d.allowed||'all';
  const mode = allowed==='all'?'all':(allowed.includes(',')?'multiple':'single');
  $$('.seg.mode-access button',form===null?document:m).forEach(x=>{ if(x.dataset.v===mode) x.click(); });
  if(mode==='single') m.querySelector('select[name=single_ep]').value=allowed;
  if(mode==='multiple'){
    $$('.pick input[name=eps]',m).forEach(c=>c.checked = allowed.split(',').map(s=>s.trim()).includes(c.value));
  }
  /* usage */
  $$('.seg.mode-usage button',m).forEach(x=>{ if(x.dataset.v===(d.usage||'unlimited')) x.click(); });
  /* validity */
  const sel=form['validity'];
  const rows=$('.row-custom-date',m);
  if(d.expires){
    sel.value='custom'; rows.style.display='block';
    form['custom_date'].value=d.expires;
  } else { sel.value='lifetime'; rows.style.display='none'; }
  openModal('#m-edit');
});

/* select-all checkbox */
const selAll=$('#selAll');
if(selAll) selAll.addEventListener('change',()=>{
  $$('.row-cb').forEach(c=>c.checked=selAll.checked);
  updateBulk();
});
document.addEventListener('change',e=>{ if(e.target.classList.contains('row-cb')) updateBulk(); });

function updateBulk(){
  const bar=$('#bulkbar'); if(!bar) return;
  const n=$$('.row-cb:checked').length;
  bar.style.display = n?'flex':'none';
  $('#bulkCount').textContent = n+' selected';
  $$('.row-cb:checked').forEach(c=>{
    const id=parseInt(c.closest('tr').dataset.id);
    if(!bar.querySelector(`input[name=ids][value="${id}"]`)){} // handled at submit
  });
}
const bulkForm=$('#bulkForm');
if(bulkForm) bulkForm.addEventListener('submit',async e=>{
  e.preventDefault();
  const ids=$$('.row-cb:checked').map(c=>c.closest('tr').dataset.id);
  if(!ids.length) return toast('Select keys first',false);
  const fd=new FormData(); ids.forEach(i=>fd.append('ids',i));
  fd.append('bulk_action',$('#bulkAction').value);
  await post($('#bulkForm').action,fd);
  toast('Done.',true); setTimeout(()=>location.reload(),450);
});

/* row actions */
document.addEventListener('click',async e=>{
  const a=e.target.closest('[data-row]'); if(!a) return;
  const d=a.dataset;
  if(d.row==='toggle'){ await post(d.url,{_t:1}); toast('Status toggled'); setTimeout(()=>location.reload(),350); }
  if(d.row==='reset'){ await post(d.url,{_t:1}); toast('Hits reset & key re-activated'); setTimeout(()=>location.reload(),350); }
  if(d.row==='delete'){ if(!confirm('Delete this key permanently?'))return; await post(d.url,{_t:1}); toast('Deleted'); setTimeout(()=>location.reload(),350); }
  if(d.row==='extend'){ await post(d.url,{days:30}); toast('Extended +30 days'); setTimeout(()=>location.reload(),350); }
  if(d.row==='download'){ location.href=d.url; }
  if(d.row==='stat'){ location.href=d.url; }
});

/* =================================================================
   ENDPOINT PAGE
================================================================= */
document.addEventListener('click',async e=>{
  const t=e.target.closest('[data-ep-test]'); if(!t) return;
  const btn=t; btn.textContent='…'; btn.disabled=true;
  try{
    const j=await post(t.dataset.epTest,{term:t.dataset.term||'1'});
    if(j.ok){ toast('Test OK · '+j.ms+'ms'); previewModal('Test result ('+j.ms+'ms)', pretty(j.preview)); }
    else { toast('Test failed: '+j.error,false); previewModal('Test failed', (j.error||'')+'  ('+j.ms+'ms)'); }
  }finally{ btn.disabled=false; btn.textContent='Test'; }
});
function pretty(s){ try{ return JSON.stringify(JSON.parse(s),null,2);}catch(_){return s;} }

document.addEventListener('click',e=>{
  const el=e.target.closest('[data-ep-edit]'); if(!el) return;
  const m=$('#m-epedit'); const f=m.querySelector('form'); f.action=el.dataset.url;
  f['name'].value=el.dataset.name||''; f['emoji'].value=el.dataset.emoji||'';
  f['url_template'].value=el.dataset.tpl||''; f['upstream_key'].value=el.dataset.ekey||'';
  openModal('#m-epedit');
});

/* =================================================================
   LOGS PAGE
================================================================= */
document.addEventListener('click',async e=>{
  const r=e.target.closest('[data-log]'); if(!r) return;
  try{
    const j=await fetch('/admin/logs/'+r.dataset.log).then(r=>r.json());
    if(!j.ok) return;
    const l=j.log;
    previewModal('Log #'+l.id, pretty(l.response_preview||'(no preview saved)')+
      `\n\nendpoint: ${l.endpoint}\nkey: ${l.key_string||''}\nterm: ${l.term||''}\nstatus: ${l.status_code}\ntime: ${l.response_time}ms\nip: ${l.ip}\nat: ${l.created_at}`);
  }catch(_){}
});

function previewModal(title, body){
  const m=$('#m-preview'); if(!m) return;
  m.querySelector('.prev-title').textContent=title;
  m.querySelector('pre').textContent=body||'';
  openModal('#m-preview');
}

/* =================================================================
   DASHBOARD banner save
================================================================= */
const bannerForm=$('#bannerForm');
if(bannerForm) bannerForm.addEventListener('submit',async e=>{
  e.preventDefault();
  await post('/admin/settings', new FormData(bannerForm));
  toast('Banner saved.');
});

/* =================================================================
   CHARTS
================================================================= */
function initCharts(){
  if(typeof Chart==='undefined') return;
  Chart.defaults.font.family='"Inter",system-ui'; Chart.defaults.color='#8b93a3';
  $$('.chart-line[data-data]').forEach(c=>{
    const data=JSON.parse(c.dataset.data); // [{d,c}]
    new Chart(c,{type:'line',data:{labels:data.map(x=>x.d.slice(5)),
      datasets:[{data:data.map(x=>x.c),borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,.18)',
        fill:true,tension:.4,pointBackgroundColor:'#3b82f6',pointRadius:3.5,borderWidth:2.5}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
        scales:{x:{grid:{color:'rgba(255,255,255,.04)'}},y:{grid:{color:'rgba(255,255,255,.04)'},beginAtZero:true}}}});
  });
  $$('.chart-donut[data-data]').forEach(c=>{
    const data=JSON.parse(c.dataset.data); // [{l,c}]
    new Chart(c,{type:'doughnut',data:{labels:data.map(x=>x.l),
      datasets:[{data:data.map(x=>x.c),
        backgroundColor:['#3b82f6','#8b5cf6','#22c55e','#06b6d4','#f59e0b','#ef4444','#ec4899','#a78bfa'],
        borderColor:'#111318',borderWidth:3,hoverOffset:6}]},
      options:{responsive:true,maintainAspectRatio:false,cutout:'68%',
        plugins:{legend:{position:'right',labels:{boxWidth:11,padding:11,font:{size:11}}}}}});
  });
}
window.addEventListener('load', initCharts);
