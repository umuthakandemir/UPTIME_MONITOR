const state={services:[],groups:[],settings:null,current:null,user:null,notifications:[]};
// Declared before bootstrap/event execution to avoid TDZ errors during early navigation.
var multiControlTypesCache=null, mcSettingsCache=null;
const $=s=>document.querySelector(s);const $$=s=>[...document.querySelectorAll(s)];
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
let apiBusy=0;function loadingStart(){apiBusy++;document.getElementById('globalProgress')?.classList.add('active')}function loadingEnd(){apiBusy=Math.max(0,apiBusy-1);if(!apiBusy)document.getElementById('globalProgress')?.classList.remove('active')}async function api(url,opt={}){loadingStart();try{const token=localStorage.getItem('sm_token');const headers={'Content-Type':'application/json',...(opt.headers||{})};if(token)headers.Authorization=`Bearer ${token}`;const r=await fetch(url,{...opt,headers});let d={};try{d=await r.json()}catch{}const detail=d.detail;const detailText=typeof detail==='string'?detail:Array.isArray(detail)?detail.map(x=>typeof x==='string'?x:(x.msg?`${x.loc?.join('.')||'alan'}: ${x.msg}`:JSON.stringify(x))).join(' | '):detail&&typeof detail==='object'?(detail.message||detail.msg||JSON.stringify(detail)):'';if(r.status===401){localStorage.removeItem('sm_token');showLogin();throw new Error(detailText||'Oturum gerekli')}if(!r.ok)throw new Error(detailText||d.message||`HTTP ${r.status}`);return d}finally{loadingEnd()}}
function toast(msg){const e=document.createElement('div');e.className='toast';e.textContent=msg;$('#toastRoot').append(e);setTimeout(()=>e.remove(),3500)}function clearScreenshotBlobCache(){for(const u of screenshotBlobCache.values())URL.revokeObjectURL(u);screenshotBlobCache.clear()}
const screenshotBlobCache=new Map();async function secureScreenshotBlob(path){if(screenshotBlobCache.has(path))return screenshotBlobCache.get(path);const token=localStorage.getItem('sm_token');const headers=token?{Authorization:`Bearer ${token}`}:{ };const r=await fetch(path,{headers,credentials:'same-origin',cache:'no-store'});if(!r.ok)throw new Error(r.status===401?'Oturum doğrulanamadı. Lütfen yeniden giriş yapın.':`Ekran görüntüsü alınamadı (HTTP ${r.status})`);const blob=await r.blob();const url=URL.createObjectURL(blob);screenshotBlobCache.set(path,url);return url}async function hydrateScreenshotImages(root=document){root.querySelectorAll?.('img[data-secure-screenshot]').forEach(async img=>{if(img.dataset.secureLoaded==='1')return;img.dataset.secureLoaded='1';try{img.src=await secureScreenshotBlob(img.dataset.secureScreenshot)}catch(e){img.dataset.secureLoaded='0';img.alt='Ekran görüntüsü yüklenemedi';img.title=e.message}})}document.addEventListener('click',async e=>{const a=e.target.closest('a[data-secure-screenshot]');if(!a)return;e.preventDefault();try{const url=await secureScreenshotBlob(a.dataset.secureScreenshot);window.open(url,'_blank','noopener')}catch(err){toast(err.message)}});new MutationObserver(muts=>muts.forEach(m=>m.addedNodes.forEach(n=>{if(n.nodeType===1){if(n.matches?.('img[data-secure-screenshot]'))hydrateScreenshotImages(n.parentNode||document);else hydrateScreenshotImages(n)}}))).observe(document.documentElement,{childList:true,subtree:true});
function theme(){const dark=document.documentElement.dataset.theme!=='light';document.documentElement.dataset.theme=dark?'light':'dark';localStorage.theme=document.documentElement.dataset.theme;$('#themeToggle').textContent=dark?'☾':'☀'}
function initTheme(){const t=localStorage.theme||'dark';document.documentElement.dataset.theme=t;$('#themeToggle').textContent=t==='dark'?'☀':'☾';$('#themeToggle').onclick=theme}
const pageNames={dashboard:'Dashboard',services:'Servisler','service-detail':'Servis Detayı',incidents:'Olaylar',notifications:'Bildirim Grupları','notification-templates':'Bildirim Şablonları',integrations:'Uygulama Entegrasyonları',reports:'Raporlar',logs:'İşlem Kayıtları',audit:'Denetim',settings:'Ayarlar',retention:'Veri Saklama',screenshots:'Ekran Görüntüleri',users:'Kullanıcılar'};
async function loadPage(name,sub){if(['settings','integrations','retention'].includes(name))document.querySelector('.settings-tree')?.classList.add('open');if(name==='integrations')document.querySelector('.settings-tree .nested-tree')?.classList.add('open'); if(name==='screenshots')document.querySelector('.service-data-tree')?.classList.add('open'); if(['services','incidents','logs','audit'].includes(name))document.querySelector('.monitor-tree')?.classList.add('open'); if(['notifications','notification-templates'].includes(name))document.querySelector('.notification-tree')?.classList.add('open'); if(name==='reports')document.querySelector('.report-tree')?.classList.add('open');$$('[data-page]').forEach(a=>a.classList.toggle('active',a.dataset.page===name));$('#pageTitle').textContent=pageNames[name]||name;$('#pageKicker').textContent='Uptime Monitor Service';const r=await fetch(`/static/pages/${name}.html`);if(!r.ok)throw new Error(`Sayfa yüklenemedi (HTTP ${r.status})`);const html=await r.text();$('#page').innerHTML=html;const init=({dashboard:dashboard,services:services,'instant-test':instantTest,'service-detail':serviceDetailPage,incidents:incidents,notifications:notifications,'notification-templates':notificationTemplates,integrations:()=>integrations(sub||'smtp'),reports:reports,logs:logs,audit:audit,settings:settings,retention:retention,screenshots:screenshots,users:users}[name]||dashboard);try{await init()}catch(e){console.error(`Page init failed: ${name}`,e);const page=$('#page');if(page&&!page.querySelector('.page-error'))page.insertAdjacentHTML('afterbegin',`<div class="page-error panel"><b>Sayfa yüklenemedi</b><p>${esc(e.message||'Beklenmeyen hata')}</p><button class="btn" onclick="loadPage('${name}')">Tekrar dene</button></div>`);throw e}}
$$('[data-page]').forEach(a=>a.addEventListener('click',e=>{if(a.classList.contains('nav-parent')){e.preventDefault();e.stopPropagation();const tree=a.closest('.nav-tree');if(tree){const willOpen=!tree.classList.contains('open');tree.classList.toggle('open',willOpen);a.setAttribute('aria-expanded',String(willOpen))}return}loadPage(a.dataset.page,a.dataset.integration).then(()=>{if(a.dataset.settingsSection==='branding')setTimeout(()=>document.getElementById('brandingCard')?.scrollIntoView({behavior:'smooth'}),50)})}));$$('.nav-parent').forEach(a=>a.setAttribute('aria-expanded',String(a.closest('.nav-tree')?.classList.contains('open')||false)));
async function refresh(){if(document.hidden)return;try{const d=await api('/api/dashboard');if(d){$('#incidentBadge').textContent=d.active_incidents??0;updateDashboardStatNumbers(d);}}catch(e){if(!String(e.message).includes('Oturum'))toast(e.message)};loadNotifications(false)}
function updateDashboardStatNumbers(d){const stats=$$('#stats .stat strong');if(stats.length>=5){stats[0].textContent=d.total??0;stats[1].textContent=d.up??0;stats[2].textContent=d.warning??0;stats[3].textContent=d.down??0;}}function updateMonitoringNotificationBadges(c={}){const counts={services:Number(c.services||0),incidents:Number(c.incidents||0)};['services','incidents'].forEach(page=>{const a=document.querySelector(`.nav-children a[data-page="${page}"]`);if(!a)return;let b=a.querySelector('.nav-sub-count');if(counts[page]>0){if(!b){b=document.createElement('i');b.className='nav-sub-count';a.appendChild(b)}b.textContent=counts[page]>99?'99+':String(counts[page])}else b?.remove()})}

let dashboardPeriod='24h';
const listState={services:{page:1,pageSize:20,q:'',status:'ALL',sort:'name_az'},logs:{page:1,pageSize:50,q:''},incidents:{page:1,pageSize:50,q:''},audit:{page:1,pageSize:50,q:''}};
function paginationHtml(key,meta){const pages=Math.max(1,Number(meta?.pages||1)),page=Math.min(pages,Math.max(1,Number(meta?.page||1)));return `<div class="pagination"><button class="mini-btn" data-pager="${key}" data-page="1" ${page<=1?'disabled':''}>« İlk</button><button class="mini-btn" data-pager="${key}" data-page="${page-1}" ${page<=1?'disabled':''}>‹ Önceki</button><span>Sayfa <b>${page}</b> / ${pages} · ${Number(meta?.total||0).toLocaleString('tr-TR')} kayıt</span><button class="mini-btn" data-pager="${key}" data-page="${page+1}" ${page>=pages?'disabled':''}>Sonraki ›</button><button class="mini-btn" data-pager="${key}" data-page="${pages}" ${page>=pages?'disabled':''}>Son »</button></div>`}

function table(headers,rows,clickable=false,rowAttrs){
  const safeHeaders=(headers||[]).map(h=>`<th>${esc(h)}</th>`).join('');
  const body=(rows||[]).map((row,i)=>{
    const attrs=clickable&&typeof rowAttrs==='function'?String(rowAttrs(row,i)||'') : '';
    return `<tr ${attrs}>${(row||[]).map(cell=>`<td>${cell==null?'':String(cell)}</td>`).join('')}</tr>`;
  }).join('');
  return `<div class="table-wrap"><table class="data-table"><thead><tr>${safeHeaders}</tr></thead><tbody>${body||`<tr><td colspan="${Math.max(1,(headers||[]).length)}"><div class="empty">Kayıt bulunamadı.</div></td></tr>`}</tbody></table></div>`;
}
function modalDetail(title,html){
  let modal=document.getElementById('detailInfoModal');
  if(!modal){
    modal=document.createElement('div');
    modal.id='detailInfoModal';
    modal.className='modal';
    document.body.appendChild(modal);
  }
  modal.innerHTML=`<div class="modal-card xwide detail-popup-card"><div class="modal-head"><div><b>${esc(title)}</b><small>Detaylı kayıt bilgileri</small></div><button type="button" class="icon-close" data-detail-close="1">×</button></div><div class="detail-popup-body">${html}</div></div>`;
  modal.classList.remove('hidden');
  const close=()=>{modal.classList.add('hidden');modal.remove()};
  modal.querySelector('[data-detail-close]')?.addEventListener('click',close);
  modal.addEventListener('click',e=>{if(e.target===modal)close()},{once:true});
  return modal;
}
async function openDetail(id){
  const sid=Number(id);
  if(!Number.isInteger(sid)||sid<=0){toast('Geçersiz servis ID.');return}
  sessionStorage.setItem('sm_detail_id',String(sid));
  await loadPage('service-detail');
}
function runFormBusy(form,submit,work){
  const target=submit||form?.querySelector('button[type="submit"]');
  if(form?.dataset.busy==='1') return Promise.resolve();
  if(form) form.dataset.busy='1';
  if(target){target.disabled=true;target.dataset.originalText=target.textContent;target.textContent='Kaydediliyor…';}
  return Promise.resolve().then(work).catch(err=>{toast(err?.message||String(err));return null}).finally(()=>{
    if(form) form.dataset.busy='0';
    if(target){target.disabled=false;target.textContent=target.dataset.originalText||'Kaydet';}
  });
}
function bindGlobalModalActions(){
  document.addEventListener('click',e=>{
    const btn=e.target.closest('[data-action], [data-page-link]');
    if(!btn)return;
    const action=btn.dataset.action;
    const pageLink=btn.dataset.pageLink;
    if(pageLink){
      e.preventDefault();
      loadPage(pageLink).catch(err=>toast(err.message||String(err)));
      return;
    }
    const map={
      'close-modal':'#serviceModal',
      'close-group':'#groupModal',
      'close-user':'#userModal',
      'close-role-defaults':'#roleDefaultsModal'
    };
    const selector=map[action];
    if(selector){e.preventDefault();document.querySelector(selector)?.classList.add('hidden');return}
    if(action==='new-service'){
      e.preventDefault();
      openService().catch(err=>toast(err.message||String(err)));
      return;
    }
    if(action==='new-group'){
      e.preventDefault();
      try{openGroup()}catch(err){toast(err.message||String(err))}
      return;
    }
    if(action==='new-user'){
      e.preventDefault();
      openUser().catch(err=>toast(err.message||String(err)));
      return;
    }
    if(action==='role-defaults'){
      e.preventDefault();
      openRoleDefaults().catch(err=>toast(err.message||String(err)));
      return;
    }
    if(action==='back-services'){
      e.preventDefault();
      loadPage('services').catch(err=>toast(err.message||String(err)));
    }
  });
}
bindGlobalModalActions();

function bindPager(rootId,key,loader){document.querySelectorAll(`#${rootId} [data-pager="${key}"]`).forEach(b=>b.addEventListener('click',()=>{if(b.disabled)return;listState[key].page=Number(b.dataset.page);loader()}))}
function bindSearch(inputId,key,loader){const el=document.getElementById(inputId);if(!el)return;el.value=listState[key].q||'';if(el.dataset.searchBound==='1')return;el.dataset.searchBound='1';let t;el.addEventListener('input',()=>{clearTimeout(t);listState[key].q=el.value.slice(0,100);listState[key].page=1;t=setTimeout(loader,180)})}
function bindPageSize(inputId,key,loader){const el=document.getElementById(inputId);if(!el)return;el.value=String(listState[key].pageSize);el.addEventListener('change',()=>{listState[key].pageSize=Number(el.value);listState[key].page=1;loader()})}
let serviceDetailPeriod='24h';
function rangeButtons(rootId, callback){const root=document.getElementById(rootId);if(!root||root.dataset.bound)return;root.dataset.bound='1';root.querySelectorAll('.range-tab').forEach(btn=>btn.addEventListener('click',()=>{root.querySelectorAll('.range-tab').forEach(x=>x.classList.remove('active'));btn.classList.add('active');callback(btn.dataset.period)}))}
function svgLineChart(data, series, opts={}){
  if(!data||!data.length)return '<div class="empty">Seçilen dönem için henüz yeterli veri yok.</div>';
  const w=900,h=270,p={l:76,r:34,t:24,b:54}; const iw=w-p.l-p.r, ih=h-p.t-p.b;
  const all=series.flatMap(x=>data.map(d=>Number(d[x.key])||0)); let max=Number(opts.max||Math.max(1,...all)); if(max<=0)max=1; const min=Number(opts.min||0);
  const x=i=>p.l+(data.length===1?iw/2:i*iw/(data.length-1)); const y=v=>p.t+(max-v)/(max-min||1)*ih;
  const grid=[0,.25,.5,.75,1].map(t=>{const yy=p.t+ih*t;const val=max-(max-min)*t;return `<line x1="${p.l}" y1="${yy}" x2="${w-p.r}" y2="${yy}" class="chart-grid-line"/><text x="${p.l-10}" y="${yy+4}" text-anchor="end" class="chart-axis">${esc(opts.format?opts.format(val):Math.round(val))}</text>`}).join('');
  const labels=data.map((d,i)=>i===0||i===data.length-1||i===Math.floor(data.length/2)?`<text x="${x(i)}" y="${h-8}" text-anchor="middle" class="chart-axis">${esc(d.label)}</text>`:'').join('');
  const paths=series.map((ser,si)=>{const pts=data.map((d,i)=>[x(i),y(Number(d[ser.key])||0)]);const line=pts.map((q,i)=>(i?'L':'M')+q[0].toFixed(1)+' '+q[1].toFixed(1)).join(' ');const area=si===0?`<path d="${line} L ${x(data.length-1)} ${p.t+ih} L ${x(0)} ${p.t+ih} Z" class="chart-area"/>`:'';const circles=pts.map((q,i)=>{const tip=`${data[i].label} · ${ser.label}: ${opts.prefix||''}${Number(data[i][ser.key]||0).toLocaleString('tr-TR',{maximumFractionDigits:2})}${opts.suffix||''}`;return `<circle cx="${q[0]}" cy="${q[1]}" r="4" class="chart-dot" tabindex="0" data-chart-tip="${esc(tip)}"/>`}).join('');return area+`<path d="${line}" class="chart-line line-${si}"/>${circles}`}).join('');
  const legend=series.map((ser,i)=>`<span class="chart-legend-item"><i class="legend-line line-${i}"></i>${esc(ser.label)}</span>`).join('');
  return `<div class="svg-chart-wrap"><svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="analytics-svg">${grid}${paths}${labels}</svg><div class="chart-legend">${legend}</div></div>`;
}
function bindChartTooltips(){
  document.querySelectorAll('.chart-dot[data-chart-tip]').forEach(dot=>{
    if(dot.dataset.bound)return; dot.dataset.bound='1';
    const show=()=>{let tip=document.getElementById('chartTooltip');if(!tip){tip=document.createElement('div');tip.id='chartTooltip';tip.className='chart-tooltip';document.body.appendChild(tip)}tip.textContent=dot.dataset.chartTip;tip.classList.add('show');const r=dot.getBoundingClientRect();tip.style.left=`${Math.min(window.innerWidth-220,Math.max(10,r.left+r.width/2))}px`;tip.style.top=`${Math.max(8,r.top-42)}px`};
    const hide=()=>document.getElementById('chartTooltip')?.classList.remove('show');
    dot.addEventListener('mouseenter',show);dot.addEventListener('mouseleave',hide);dot.addEventListener('focus',show);dot.addEventListener('blur',hide);
  });
}
function renderDonut(target,counts){const total=Math.max(1,(counts.UP||0)+(counts.WARNING||0)+(counts.DOWN||0));const up=(counts.UP||0)/total*100,down=up+(counts.DOWN||0)/total*100;target.innerHTML=`<div class="donut chart-hover" data-chart-tip="UP: ${counts.UP||0} · WARNING: ${counts.WARNING||0} · DOWN: ${counts.DOWN||0} · Toplam: ${total}" style="--up:${up}%;--down:${down}%"><div class="donut-center"><b>${Math.round(up)}%</b><small>UP</small></div></div><div class="legend"><span><i class="dot" style="background:var(--accent)"></i>UP ${counts.UP||0}</span><span><i class="dot" style="background:var(--danger)"></i>DOWN ${counts.DOWN||0}</span><span><i class="dot" style="background:var(--warn)"></i>WARN ${counts.WARNING||0}</span></div>`;const el=target.querySelector('.chart-hover');if(el){el.onmouseenter=()=>showDashboardTip(el);el.onmouseleave=hideDashboardTip}}
function renderHbars(target,items,labelKey,valueKey,format=(v)=>v){if(!items.length){target.innerHTML='<div class="empty">Veri yok.</div>';return}const max=Math.max(1,...items.map(x=>Number(x[valueKey])||0));target.innerHTML=items.map(x=>`<div class="hbar-row rich"><div class="hbar-label"><span title="${esc(x[labelKey])}">${esc(x[labelKey])}</span><small>${format(Number(x[valueKey])||0)}</small></div><div class="hbar-track"><i style="width:${Math.max(2,(Number(x[valueKey])||0)/max*100)}%"></i></div></div>`).join('')}
function openGroup(g={}){
 $('#groupModal').classList.remove('hidden');
 $('#groupForm').innerHTML=`<div class="field"><label>Grup adı</label><input name="name" value="${esc(g.name||'Yeni Grup')}"></div><label class="switch"><span>Yeni servislere otomatik ata</span><input name="auto_add_new_services" type="checkbox" ${g.auto_add_new_services?'checked':''}><span class="track"></span></label><div class="section-box"><h4>Bildirim Kanalları</h4><small class="field-help">Telegram ve diğer uygulama bağlantıları Ayarlar → Uygulama Entegrasyonları bölümünden merkezi olarak yapılandırılır.</small><label class="switch"><span>E-posta</span><input name="email" type="checkbox" ${g.channels?.email?'checked':''}><span class="track"></span></label><div class="field"><label>E-posta alıcıları (virgülle)</label><input name="emails" value="${esc((g.recipients?.email||[]).join(', '))}"></div><label class="switch"><span>Webhook</span><input name="webhook" type="checkbox" ${g.channels?.webhook?'checked':''}><span class="track"></span></label><div class="field"><label>Webhook URL</label><input name="webhook_url" value="${esc(g.recipients?.webhook_url||'')}" placeholder="https://..."></div><label class="switch"><span>Discord</span><input name="discord" type="checkbox" ${g.channels?.discord?'checked':''}><span class="track"></span></label><label class="switch"><span>Slack</span><input name="slack" type="checkbox" ${g.channels?.slack?'checked':''}><span class="track"></span></label><label class="switch telegram-channel"><span>Telegram</span><input name="telegram" type="checkbox" ${g.channels?.telegram?'checked':''}><span class="track"></span></label></div><div class="actions"><button type="button" class="btn" data-action="close-group">İptal</button><button class="btn primary">Kaydet</button></div>`;
 const tf=$('#groupForm');tf.onsubmit=async e=>{e.preventDefault();const f=e.target,v=Object.fromEntries(new FormData(f));const channels={email:f.email.checked,webhook:f.webhook.checked,discord:f.discord.checked,slack:f.slack.checked,telegram:f.telegram.checked};const recipients={email:(v.emails||'').split(',').map(x=>x.trim()).filter(Boolean),webhook_url:v.webhook_url,discord_webhook:'',slack_webhook:''};await api(g.id?`/api/groups/${g.id}`:'/api/groups',{method:g.id?'PUT':'POST',body:JSON.stringify({name:v.name,enabled:true,auto_add_new_services:f.auto_add_new_services.checked,channels,recipients})});toast('Bildirim grubu kaydedildi');$('#groupModal').classList.add('hidden');notifications()}
}
let notificationsLoadPromise=null;async function notifications(){if(notificationsLoadPromise)return notificationsLoadPromise;notificationsLoadPromise=(async()=>{const host=$('#groupsList');if(!host)return;host.innerHTML='<div class="empty">Bildirim grupları yükleniyor…</div>';try{const groups=await api('/api/groups');state.groups=Array.isArray(groups)?groups:[];host.innerHTML=state.groups.map(g=>`<div class="panel"><div class="panel-head"><div><b>${esc(g.name)}</b><small>${g.auto_add_new_services?'Yeni servislere otomatik atanır':'Manuel atanır'}</small></div><span class="badge good">${Object.entries(g.channels||{}).filter(x=>x[1]).map(x=>x[0]).join(' + ')||'Kanal yok'}</span></div><p class="muted">E-posta: ${((g.recipients||{}).email||[]).join(', ')||'-'}</p><div class="actions"><button class="mini-btn" onclick='openGroup(${JSON.stringify(g)})'>Düzenle</button><button class="mini-btn" onclick='deleteGroup(${g.id})'>Sil</button></div></div>`).join('')||'<div class="empty">Henüz bildirim grubu yok.</div>'}catch(e){host.innerHTML=`<div class="page-error panel"><b>Bildirim grupları yüklenemedi</b><p>${esc(e.message||'Sunucu yanıt vermedi')}</p><button class="btn" onclick="notifications()">Tekrar dene</button></div>`;throw e}finally{notificationsLoadPromise=null}})();return notificationsLoadPromise}
async function deleteGroup(id){if(!confirm('Grup silinsin mi?'))return;await api(`/api/groups/${id}`,{method:'DELETE'});notifications()}
async function openRoleDefaults(){if(state.user?.role!=='super_admin'){toast('Rol varsayılanlarını yalnızca Super Admin değiştirebilir');return}const meta=await api('/api/roles');const roles=(meta.roles||[]).filter(r=>['admin','read_only_admin'].includes(r.key));const names=Object.fromEntries((meta.permissions||[]).map(x=>[x.key,x.name]));const groups={Dashboard:['dashboard.view'],Servisler:['services.view','services.create','services.update','services.delete','services.security','services.screenshot'],Test:['instant_test.execute'],Bildirim:['groups.view','groups.create','groups.update','groups.delete','notifications.view','notifications.manage','notification_templates.view','notification_templates.update'],Ayarlar:['settings.view','settings.update','integrations.view','integrations.update','retention.view','retention.update'],Kayıtlar:['logs.view','incidents.view','audit.view','reports.view','reports.export'],Kullanıcılar:['users.view','users.create','users.update','users.delete']};$('#roleDefaultsModal').classList.remove('hidden');const renderRole=async role=>{const d=await api(`/api/roles/${role}/permissions`);const selected=new Set(d.permissions||[]);$('#roleDefaultsBody').innerHTML=`<div class="role-default-toolbar"><label>Rol<select id="roleDefaultSelect">${roles.map(r=>`<option value="${r.key}" ${r.key===role?'selected':''}>${r.name}</option>`).join('')}</select></label><button class="btn primary" id="saveRoleDefaults">Rol Varsayılanlarını Kaydet</button></div><div class="permission-editor">${Object.entries(groups).map(([g,keys])=>`<div class="permission-group"><div class="permission-group-title">${g}</div>${keys.map(k=>`<label class="permission-check"><input type="checkbox" name="rolePermission" value="${k}" ${selected.has(k)?'checked':''}><span><b>${esc(names[k]||k)}</b><small>${k}</small></span></label>`).join('')}</div>`).join('')}</div>`;$('#roleDefaultSelect').onchange=()=>renderRole($('#roleDefaultSelect').value);$('#saveRoleDefaults').onclick=async()=>{const permissions=$$('#roleDefaultsBody input[name="rolePermission"]:checked').map(x=>x.value);await api(`/api/roles/${role}/permissions`,{method:'PUT',body:JSON.stringify({permissions})});toast('Rol varsayılanları kaydedildi');renderRole(role)}};await renderRole(roles[0]?.key||'admin')}
async function users(){const list=await api('/api/users');if($('#roleDefaultsBtn'))$('#roleDefaultsBtn').style.display=state.user?.role==='super_admin'?'':'none';const canManage=state.user?.role==='super_admin'||(state.user?.permissions||[]).includes('users.update');$('#newUserBtn').style.display=(state.user?.role==='super_admin'||(state.user?.permissions||[]).includes('users.create'))?'':'none';$('#usersList').innerHTML=list.map(u=>`<div class="user-row"><div><b>${esc(u.username)}</b><small>${esc(u.display_name||'-')} · ${esc(u.email||'E-posta yok')}</small></div><div><span class="badge">${esc(({super_admin:'Super Admin',admin:'Admin',read_only_super_admin:'Super Admin Read Only',read_only_admin:'Admin Read Only',semi_admin:'Semi Admin',read_only_semi_admin:'Semi Admin Read Only'})[u.role]||u.role)}</span> <span class="badge ${u.is_active?'good':'bad'}">${u.is_active?'AKTİF':'PASİF'}</span></div><div class="actions">${canManage?`<button class="mini-btn" onclick='openUser(${JSON.stringify(u)})'>Düzenle</button>`:''}${u.email&&!u.email_verified&&state.user?.role==='super_admin'?`<button class="mini-btn" onclick="sendVerify(${u.id})">Doğrulama Maili</button>`:''}${u.is_initial_admin?'':(state.user?.role==='super_admin'?'<button class="mini-btn danger" onclick="deleteUser('+u.id+')">Sil</button>':'')}</div></div>`).join('')||'<div class="empty">Kullanıcı yok.</div>'}
async function openUser(u={}){const meta=await api('/api/roles');const roles=meta.roles||[];$('#userModal').classList.remove('hidden');$('#userModalTitle').textContent=u.id?'Kullanıcıyı Düzenle':'Kullanıcı Ekle';const selected=new Set(u.permissions||[]);const groups={Dashboard:['dashboard.view'],Servisler:['services.view','services.create','services.update','services.delete','services.security','services.screenshot'],Test:['instant_test.execute'],Bildirim:['groups.view','groups.create','groups.update','groups.delete','notifications.view','notifications.manage','notification_templates.view','notification_templates.update'],Ayarlar:['settings.view','settings.update','integrations.view','integrations.update','retention.view','retention.update'],Kayıtlar:['logs.view','incidents.view','audit.view','reports.view','reports.export'],Kullanıcılar:['users.view','users.create','users.update','users.delete']};const permName=Object.fromEntries((meta.permissions||[]).map(x=>[x.key,x.name]));const permissionHtml=Object.entries(groups).map(([g,keys])=>`<div class="permission-group"><div class="permission-group-title">${g}</div>${keys.map(k=>`<label class="permission-check"><input type="checkbox" name="permission" value="${k}" ${selected.has(k)?'checked':''}><span><b>${esc(permName[k]||k)}</b><small>${k}</small></span></label>`).join('')}</div>`).join('');$('#userForm').innerHTML=`<div class="field"><label>Kullanıcı adı</label><input name="username" required value="${esc(u.username||'')}"></div><div class="field"><label>Şifre ${u.id?'(değiştirmeyeceksen boş bırak)':''}</label><input name="password" type="password" ${u.id?'':'required'}></div><div class="field"><label>Rol</label><select name="role">${roles.map(x=>`<option value="${x.key}" ${u.role===x.key?'selected':''}>${x.name}</option>`).join('')}</select></div><div class="field"><label>Görünen ad</label><input name="display_name" value="${esc(u.display_name||'')}"></div><div class="field"><label>E-posta</label><input name="email" type="email" value="${esc(u.email||'')}" placeholder="monitor@kurum.local"></div><label class="switch"><span>Hesap aktif</span><input name="is_active" type="checkbox" ${u.is_active!==false?'checked':''}><span class="track"></span></label><label class="switch"><span>İlk girişte şifre değişsin</span><input name="must_change_password" type="checkbox" ${u.id?(u.must_change_password?'checked':''):'checked'}><span class="track"></span></label><div class="permission-editor"><div class="panel-head"><div><b>Yetkiler</b><small>Admin için rol varsayılanları; Semi Admin için kullanıcıya özel yetkiler. Read Only roller yalnızca izleme yetkilerini kullanır.</small></div><button type="button" class="mini-btn" id="selectAllPermissions">Tümünü Seç</button></div>${permissionHtml}</div><div class="actions"><button type="button" class="btn" data-action="close-user">İptal</button><button class="btn primary">Kaydet</button></div>`;$('#selectAllPermissions').onclick=()=>{$$('#userForm input[name="permission"]').forEach(x=>x.checked=true)};$('#userForm').onsubmit=async e=>{e.preventDefault();const f=e.target;const submit=f.querySelector('button[type="submit"]');await runFormBusy(f,submit,async()=>{const v=Object.fromEntries(new FormData(f));v.is_active=f.is_active.checked;v.must_change_password=f.must_change_password.checked;if(!v.password)delete v.password;const saved=await api(u.id?`/api/users/${u.id}`:'/api/users',{method:u.id?'PUT':'POST',body:JSON.stringify(v)});const perms=$$('#userForm input[name="permission"]:checked').map(x=>x.value);if(u.id)await api(`/api/users/${u.id}/permissions`,{method:'PUT',body:JSON.stringify({permissions:perms})});else if(saved.id)await api(`/api/users/${saved.id}/permissions`,{method:'PUT',body:JSON.stringify({permissions:perms})});$('#userModal').classList.add('hidden');toast('Kullanıcı ve yetkileri kaydedildi');users()})}}
async function sendVerify(id){try{const r=await api(`/api/auth/verify-email-request/${id}`,{method:'POST'});toast(r.message)}catch(e){toast(e.message)}}
async function deleteUser(id){if(!confirm('Kullanıcı silinsin mi?'))return;await api(`/api/users/${id}`,{method:'DELETE'});users()}
async function notificationTemplates(){
 const d=await api('/api/notification-templates');
 const map={DownSubject:'down_notification_subject',DownMessage:'down_notification_message',RecoverySubject:'recovery_notification_subject',RecoveryMessage:'recovery_notification_message',WarningSubject:'warning_notification_subject',WarningMessage:'warning_notification_message',LatencySubject:'latency_notification_subject',LatencyMessage:'latency_notification_message'};
 Object.entries(map).forEach(([id,key])=>{const e=$('#tpl'+id);if(e)e.value=d[key]||''});
 $$('.template-card-head').forEach(b=>b.onclick=()=>b.parentElement.querySelector('.template-card-body').classList.toggle('open'));
 $('#saveNotificationTemplates').onclick=async()=>{const p={};Object.entries(map).forEach(([id,key])=>p[key]=$('#tpl'+id)?.value||'');await api('/api/notification-templates',{method:'PUT',body:JSON.stringify(p)});toast('Bildirim şablonları kaydedildi')};
}

async function renderIntegrations(host,only){
 const d=await api('/api/providers');const el=document.querySelector(host);if(!el)return;
 const by=Object.fromEntries(d.map(x=>[x.provider,x]));const tg=by.telegram||{provider:'telegram',enabled:false,config:{}};const wh=by.webhook||{provider:'webhook',enabled:false,config:{}};
 if(only==='telegram'){
  el.innerHTML=`<div class="panel integration-card"><div class="panel-head"><div><b>Telegram</b><small>Bot üzerinden bildirim gönderimi.</small></div><span class="badge ${tg.enabled?'good':'warn'}">${tg.enabled?'AKTİF':'PASİF'}</span></div><div class="form-grid"><div class="field"><label>Bot Token</label><input id="tgToken" type="password" placeholder="Yeni token${tg.config?.token?' (kayıtlı korunur)':''}"></div><div class="field"><label>Chat ID</label><input id="tgChat" value="${esc(tg.config?.chat_id||'')}" placeholder="-100... veya kullanıcı ID"></div><div class="field"><label>Parse Mode</label><select id="tgParse"><option value="HTML" ${(tg.config?.parse_mode||'HTML')==='HTML'?'selected':''}>HTML</option><option value="MarkdownV2" ${(tg.config?.parse_mode||'')==='MarkdownV2'?'selected':''}>MarkdownV2</option><option value="" ${!tg.config?.parse_mode?'selected':''}>Plain text</option></select></div><label class="switch"><span>Etkin</span><input id="tgEnabled" type="checkbox" ${tg.enabled?'checked':''}><span class="track"></span></label></div><div class="actions"><button type="button" class="mini-btn" id="tgTest">Bağlantıyı Test Et</button><button type="button" class="btn primary" id="tgSave">Telegram'ı Kaydet</button></div><div id="tgStatus" class="form-status"></div></div>`;
  $('#tgSave').onclick=async()=>{const token=$('#tgToken').value.trim()||tg.config?.token||'';await api('/api/providers',{method:'POST',body:JSON.stringify({provider:'telegram',enabled:$('#tgEnabled').checked,config:{token,chat_id:$('#tgChat').value.trim(),parse_mode:$('#tgParse').value}})});toast('Telegram kaydedildi');integrations('telegram')};
  $('#tgTest').onclick=async()=>{try{const r=await api('/api/telegram/test',{method:'POST'});$('#tgStatus').textContent=r.message||'Test tamamlandı';toast(r.message||'Telegram testi tamamlandı')}catch(e){$('#tgStatus').textContent=e.message;toast(e.message)}};
  return;
 }
 if(only==='webhook'){
  const cfg=wh.config||{};el.innerHTML=`<div class="panel integration-card"><div class="panel-head"><div><b>Webhook</b><small>Genel HTTP webhook bildirim sağlayıcısı.</small></div><span class="badge ${wh.enabled?'good':'warn'}">${wh.enabled?'AKTİF':'PASİF'}</span></div><div class="form-grid"><div class="field full"><label>Webhook URL</label><input id="whUrl" value="${esc(cfg.url||'')}" placeholder="https://monitor.example/api/hook"></div><div class="field"><label>HTTP Method</label><select id="whMethod"><option ${String(cfg.method||'POST')==='POST'?'selected':''}>POST</option><option ${String(cfg.method||'POST')==='PUT'?'selected':''}>PUT</option></select></div><div class="field"><label>Content-Type</label><input id="whContent" value="${esc(cfg.content_type||'application/json')}"></div><div class="field full"><label>Header JSON (opsiyonel)</label><textarea id="whHeaders" rows="4">${esc(JSON.stringify(cfg.headers||{},null,2))}</textarea></div><label class="switch"><span>Etkin</span><input id="whEnabled" type="checkbox" ${wh.enabled?'checked':''}><span class="track"></span></label></div><div class="actions"><button type="button" class="btn primary" id="whSave">Webhook'u Kaydet</button></div></div>`;
  $('#whSave').onclick=async()=>{let headers={};try{headers=JSON.parse($('#whHeaders').value||'{}')}catch{toast('Header JSON geçerli değil');return}await api('/api/providers',{method:'POST',body:JSON.stringify({provider:'webhook',enabled:$('#whEnabled').checked,config:{url:$('#whUrl').value.trim(),method:$('#whMethod').value,content_type:$('#whContent').value.trim(),headers}})});toast('Webhook kaydedildi');integrations('webhook')};return;
 }
 el.innerHTML='<div class="empty">Entegrasyon seçin.</div>';
}
async function saveProvider(p){const cfg=JSON.parse(document.querySelector(`[data-provider="${p}"].provider-json`).value||'{}');const en=document.querySelector(`.provider-enabled[data-provider="${p}"]`).checked;await api('/api/providers',{method:'POST',body:JSON.stringify({provider:p,enabled:en,config:cfg})});toast('Entegrasyon kaydedildi')}
async function incidents(){const st=listState.incidents;try{const d=await api(`/api/incidents?q=${encodeURIComponent(st.q)}&page=${st.page}&page_size=${st.pageSize}`);$('#incidentsTable').innerHTML=table(['Durum','Servis / Kontrol','Başlangıç','Çözülme','Süre','Neden'],(d.items||[]).map(x=>[x.status,`<button class="table-link" onclick="event.stopPropagation();showIncidentDetail(${x.id})">Servis #${x.service_id||'-'} · Kontrol #${x.control_id||'-'}</button>`,x.started,x.resolved||'-',Math.round(x.duration||0)+' sn',x.reason||'-'],true,x=>`onclick="showIncidentDetail(${x.id})"`));$('#incidentsPager').innerHTML=paginationHtml('incidents',d);bindPager('incidentsPager','incidents',incidents)}catch(e){toast(e.message)}bindSearch('incidentsSearch','incidents',incidents);bindPageSize('incidentsPageSize','incidents',incidents)}
async function logs(){const st=listState.logs;try{const d=await api(`/api/logs?q=${encodeURIComponent(st.q)}&page=${st.page}&page_size=${st.pageSize}`);const rows=(d.items||[]).map(x=>`<tr class="log-row" data-log-id="${x.id}"><td><span class="badge ${x.level==='ERROR'?'bad':x.level==='WARNING'?'warn':'good'}">${esc(x.level)}</span></td><td>${esc(x.category)}</td><td>${esc(notificationTime(x.time))}</td><td>${x.service_id?`<div class="log-service-cell"><b>${esc(x.service_name||`Servis #${x.service_id}`)}</b><small>${esc(x.monitor_type||'-')} · #${x.service_id}</small></div>`:'<span class="muted">Sistem</span>'}</td><td class="log-message-cell" title="${esc(x.message||'')}">${esc(x.message||'-')}</td></tr>`).join('');$('#logsTable').innerHTML=rows?`<table class="data-table logs-data-table"><thead><tr><th>Seviye</th><th>Kategori</th><th>Zaman</th><th>Servis</th><th>Mesaj</th></tr></thead><tbody>${rows}</tbody></table>`:'<div class="empty">Kayıt bulunamadı.</div>';$$('#logsTable .log-row').forEach(row=>row.onclick=()=>showLogDetail(Number(row.dataset.logId)));$('#logsPager').innerHTML=paginationHtml('logs',d);bindPager('logsPager','logs',logs)}catch(e){toast(e.message)}bindSearch('logsSearch','logs',logs);bindPageSize('logsPageSize','logs',logs)}
async function showLogDetail(id){try{const d=await api(`/api/logs/${id}`);const s=d.service;const checks=(d.recent_checks||[]).map(x=>`<div class="detail-check-row"><span class="badge ${x.status==='DOWN'?'bad':x.status==='WARNING'?'warn':'good'}">${esc(x.status)}</span><b>${x.http_status??'-'}</b><span>${Math.round(x.latency_ms||0)} ms</span><small>${esc(notificationTime(x.time)||'-')}</small><span>${esc(x.error||'Başarılı')}</span></div>`).join('');const incidents=(d.incidents||[]).map(x=>`<div class="related-item"><b>#${x.id} · ${esc(x.status)}</b><span>${esc(notificationTime(x.started))} → ${esc(x.resolved?notificationTime(x.resolved):'Devam ediyor')}</span><small>${esc(x.reason||'-')} · ${Math.round(x.duration||0)} sn</small></div>`).join('');const shots=(d.screenshots||[]).map(x=>`<a class="related-item related-link" href="#" data-secure-screenshot="${esc(x.path)}" target="_blank"><b>${esc(x.status)} · HTTP ${x.http_status??'-'}</b><span>${esc(notificationTime(x.captured_at))}</span><small>${esc(x.reason||'-')}</small></a>`).join('');modalDetail(`Log #${id}`,`<div class="detail-log-hero"><span class="badge ${d.log.level==='ERROR'?'bad':d.log.level==='WARNING'?'warn':'good'}">${esc(d.log.level)}</span><b>${esc(d.log.category)}</b><span>${esc(notificationTime(d.log.time))}</span></div><div class="detail-message">${esc(notificationValue(d.log.message||'-'))}</div><div class="form-grid"><div class="field"><label>Servis</label><input readonly value="${esc(s?`${s.name} (#${s.id})`:'Sistem')}"></div><div class="field"><label>Son durum</label><input readonly value="${esc(s?.last_status||'-')}"></div><div class="field"><label>URL / Hedef</label><input readonly value="${esc(s?.url||s?.monitor_type||'-')}"></div><div class="field"><label>IP</label><input readonly value="${esc(s?.resolved_ip||'-')}"></div><div class="field"><label>HTTP</label><input readonly value="${s?.last_http_status??'-'}"></div><div class="field"><label>Latency</label><input readonly value="${Math.round(s?.last_latency_ms||0)} ms"></div></div><section class="detail-related"><h4>İlgili son kontroller</h4><div class="detail-check-list">${checks||'<div class="empty">Kontrol yok.</div>'}</div></section><section class="detail-related"><h4>İlgili olaylar</h4><div class="related-list">${incidents||'<div class="empty">Olay yok.</div>'}</div></section><section class="detail-related"><h4>İlgili ekran görüntüleri</h4><div class="related-list">${shots||'<div class="empty">Ekran görüntüsü yok.</div>'}</div></section><section class="detail-related"><h4>Security / TLS</h4><details><summary>Header Security</summary><pre class="code-preview">${esc(JSON.stringify(d.recent_checks?.[0]?.header_security||{},null,2))}</pre></details><details><summary>TLS Security</summary><pre class="code-preview">${esc(JSON.stringify(d.recent_checks?.[0]?.tls_security||{},null,2))}</pre></details></section>`)}catch(e){toast(e.message)}}
async function showIncidentDetail(id){try{const d=await api(`/api/incidents/${id}`);const s=d.service;const checks=(d.checks||[]).map(x=>`<div class="detail-check-row"><span class="badge ${x.status==='DOWN'?'bad':x.status==='WARNING'?'warn':'good'}">${esc(x.status)}</span><b>${x.http_status??'-'}</b><span>${Math.round(x.latency_ms||0)} ms</span><small>${esc(x.time||'-')}</small><span>${esc(x.error||'Başarılı')}</span></div>`).join('');modalDetail(`Olay #${id}`,`<div class="detail-log-hero"><span class="badge ${d.incident.status==='OPEN'?'bad':'good'}">${esc(d.incident.status)}</span><b>${esc(s?.name||'Sistem')}</b><span>Başlangıç: ${esc(d.incident.started)}</span></div><div class="incident-summary-grid"><div><small>Çözülme</small><b>${esc(d.incident.resolved||'-')}</b></div><div><small>Kesinti</small><b>${Math.round(d.incident.duration||0)} sn</b></div><div><small>Ardışık hata</small><b>${d.incident.failure_count??0}</b></div></div><div class="detail-message"><b>Neden</b><p>${esc(d.incident.reason||'-')}</p></div><h4>İlgili servis kontrolleri</h4><div class="detail-check-list">${checks||'<div class="empty">İlgili kontrol kaydı yok.</div>'}</div>`)}catch(e){toast(e.message)}}

function securityFindingClass(sev){return sev==='critical'?'bad':sev==='warning'?'warn':'good'}
function instantFieldHtml(type){
  const commonTimeout=`<div class="field"><label>Zaman aşımı (sn)</label><input name="timeout" type="number" min="1" max="120" value="8"></div>`;
  if(type==='ping') return `<div class="instant-field-note"><span>◎</span><div><b>Ping testi</b><small>ICMP ping için port gerekmez. Hedefe ağ seviyesinde erişilebilirlik ve gecikme ölçülür.</small></div></div>${commonTimeout}`;
  if(type==='dns') return `<div class="field"><label>Beklenen IP <small>(opsiyonel)</small></label><input name="expected" placeholder="Örn. 10.10.10.20"></div>`;
  if(type==='tcp') return `<div class="field"><label>Port</label><input name="port" type="number" min="1" max="65535" value="443"></div>${commonTimeout}`;
  if(type==='ssl') return `<div class="field"><label>TLS Portu</label><input name="port" type="number" min="1" max="65535" value="443"></div><div class="instant-field-note"><span>◆</span><div><b>Derin TLS analizi</b><small>Protokoller, cipher'lar, sertifika, zayıf kriptografi, renegotiation, Heartbleed/ROBOT/CCS ve mümkünse Qualys SSL Labs grade'i analiz edilir.</small></div></div>`;
  if(type==='smtp') return `<div class="instant-grid-3"><div class="field"><label>Port</label><input name="port" type="number" min="1" max="65535" value="587"></div><div class="field"><label>Kullanıcı <small>(opsiyonel)</small></label><input name="username"></div><div class="field"><label>Şifre <small>(opsiyonel)</small></label><input name="password" type="password"></div></div><div class="instant-checks"><label class="switch"><span>STARTTLS</span><input name="tls" type="checkbox" checked><span class="track"></span></label><label class="switch"><span>SSL</span><input name="ssl" type="checkbox"><span class="track"></span></label></div>`;
  if(type==='mysql') return `<div class="instant-grid-4"><div class="field"><label>Port</label><input name="port" type="number" value="3306"></div><div class="field"><label>Kullanıcı</label><input name="username"></div><div class="field"><label>Şifre</label><input name="password" type="password"></div><div class="field"><label>Veritabanı</label><input name="database"></div></div>`;
  if(type==='postgresql') return `<div class="instant-grid-4"><div class="field"><label>Port</label><input name="port" type="number" value="5432"></div><div class="field"><label>Kullanıcı</label><input name="username"></div><div class="field"><label>Şifre</label><input name="password" type="password"></div><div class="field"><label>Veritabanı</label><input name="database"></div></div>`;
  if(type==='redis') return `<div class="instant-grid-4"><div class="field"><label>Port</label><input name="port" type="number" value="6379"></div><div class="field"><label>Kullanıcı <small>(opsiyonel)</small></label><input name="username"></div><div class="field"><label>Şifre <small>(opsiyonel)</small></label><input name="password" type="password"></div><div class="field"><label>DB</label><input name="database" type="number" value="0" min="0"></div></div>`;
  if(type==='web'||type==='headers'||type==='auto') return `<div class="instant-field-note"><span>◉</span><div><b>HTTP/HTTPS testi</b><small>URL üzerindeki protokol ve port otomatik kullanılır. Web testi başarısız olursa sunucu erişilebilirliği ayrıca ping ile değerlendirilir.</small></div></div>`;
  return '';
}
function instantVisual(r){
 const tls=r.tls_security||{},hs=r.header_security||{},lat=Number(r.latency_ms||0),status=r.status||'UNKNOWN';
 const score=hs.score??tls.score;
 if(r.test_type==='ssl'){
  const versions=Object.entries(tls.tls_versions||{});return `<section class="instant-chart-panel"><div class="instant-chart-title"><b>TLS sürüm haritası</b><span>SSL/TLS güvenlik skoru ${tls.grade||'-'} · ${tls.score??0}/100</span></div><div class="metric-bars">${versions.map(([v,x])=>`<div class="metric-bar"><div><span>${esc(v)}</span><b>${x.supported?'Açık':'Kapalı'}</b></div><i style="width:${x.supported?100:8}%"></i></div>`).join('')}</div></section>`;
 }
 if(r.test_type==='headers'||r.test_type==='web'){
  const checks=hs.checks||[];return `<section class="instant-chart-panel"><div class="instant-chart-title"><b>HTTP güvenlik / cevap özeti</b><span>${hs.grade||'-'} · ${hs.score??0}/100</span></div><div class="metric-bars"><div class="metric-bar"><div><span>Security Headers</span><b>${hs.score??0}/100</b></div><i style="width:${Math.max(2,Number(hs.score||0))}%"></i></div><div class="metric-bar"><div><span>Latency</span><b>${Math.round(lat)} ms</b></div><i style="width:${Math.min(100,Math.max(4,100-Math.min(lat,1000)/10))}%"></i></div><div class="metric-bar"><div><span>Header kontrolleri</span><b>${checks.filter(x=>x.status==='PASS').length}/${checks.length||0} PASS</b></div><i style="width:${checks.length?Math.max(2,checks.filter(x=>x.status==='PASS').length/checks.length*100):2}%"></i></div></div></section>`;
 }
 return `<section class="instant-chart-panel"><div class="instant-chart-title"><b>${r.test_type==='ping'?'Ping gecikme grafiği':'Test ölçüm grafiği'}</b><span>${esc(status)}</span></div><div class="metric-bars"><div class="metric-bar"><div><span>Latency</span><b>${Math.round(lat)} ms</b></div><i style="width:${Math.min(100,Math.max(6,100-Math.min(lat,1000)/10))}%"></i></div><div class="metric-bar"><div><span>Erişilebilirlik</span><b>${status==='UP'?'100%':'0%'}</b></div><i style="width:${status==='UP'?100:8}%"></i></div></div></section>`;
}
function renderInstantResult(r){
  const status=r.status||'UNKNOWN', statusClass=status==='UP'?'good':status==='WARNING'?'warn':'bad';
  const cert=r.certificate||{}, tls=r.tls_security||{}, hs=r.header_security||{}, sslLabs=tls.ssl_labs||{};
  const certDays=cert.expires_at?Math.ceil((new Date(cert.expires_at)-Date.now())/86400000):null;
  const summary=[['Durum',status],['Latency',r.latency_ms!=null?`${Math.round(r.latency_ms)} ms`:'-'],['HTTP',r.http_status??'-'],['IP',r.resolved_ip||'-'],['Port',r.port??'-']];
  const cards=summary.map(x=>`<div class="instant-kpi"><small>${x[0]}</small><b>${esc(x[1])}</b></div>`).join('');
  const certHtml=(cert.subject||cert.issuer||cert.expires_at)?`<section class="instant-section"><div class="instant-section-head"><div><b>Sertifika</b><small>Kimlik, geçerlilik ve kullanılan cipher</small></div><span class="badge ${certDays!=null&&certDays<30?'warn':'good'}">${certDays!=null?`${certDays} gün`: 'OK'}</span></div><div class="result-grid"><div><small>Common Name</small><b>${esc(cert.subject||'-')}</b></div><div><small>Issuer</small><b>${esc(cert.issuer||'-')}</b></div><div><small>Bitiş</small><b>${esc(cert.expires_at||'-')}</b></div><div><small>Cipher</small><b>${esc(cert.cipher||'-')}</b></div><div><small>SAN</small><b>${esc((cert.san||[]).join(', ')||'-')}</b></div><div><small>İmza algoritması</small><b>${esc(cert.signature_algorithm||'-')}</b></div><div><small>Anahtar tipi</small><b>${esc(cert.public_key_type||'-')}</b></div></div></section>`:'';
  const tlsHtml=tls&&Object.keys(tls).length?`<section class="instant-section"><div class="instant-section-head"><div><b>TLS / SSL Güvenlik</b><small>${esc(tls.summary||'Derin TLS değerlendirmesi')}</small></div><span class="badge ${String(tls.grade||'').startsWith('A')?'good':tls.grade==='B'?'warn':'bad'}">${esc(tls.grade||'-')} · ${tls.score??0}/100</span></div><div class="tls-source-row"><span>Yerel motor: ${esc(tls.engine||'-')}</span>${sslLabs.available?`<span class="badge good">SSL Labs: ${esc(sslLabs.grade||'-')}</span>`:`<span class="badge">SSL Labs: ${esc(sslLabs.status||sslLabs.error||'kullanılamadı')}</span>`}</div><div class="tls-version-grid">${Object.entries(tls.tls_versions||{}).map(([v,x])=>`<div class="tls-version"><b>${v}</b><span class="badge ${x.supported?'bad':'good'}">${x.supported?'Açık':'Kapalı'}</span></div>`).join('')}</div>${(tls.findings||[]).map(f=>`<div class="finding ${securityFindingClass(f.severity)}"><b>${esc(f.title)}</b><span>${esc(f.detail)}</span></div>`).join('')||'<div class="finding good"><b>Belirgin kritik TLS bulgusu yok.</b></div>'}</section>`:'';
  const headerHtml=hs&&hs.checks?`<section class="instant-section"><div class="instant-section-head"><div><b>HTTP Security Headers</b><small>Yanıt başlıklarının güvenlik analizi</small></div><span class="badge ${hs.grade&&hs.grade.startsWith('A')?'good':hs.grade==='B'?'warn':'bad'}">${esc(hs.grade||'-')} · ${hs.score??0}/100</span></div><div class="security-header-grid">${hs.checks.map(x=>`<div class="security-header-row"><span class="badge ${x.status==='PASS'?'good':x.status==='NOT_APPLICABLE'?'':'bad'}">${x.status==='PASS'?'PASS':x.status==='NOT_APPLICABLE'?'N/A':'FAIL'}</span><b>${esc(x.header)}</b><code>${esc(x.value||'Eksik')}</code></div>`).join('')}</div></section>`:'';
  const dbHtml=r.dns_addresses?.length?`<section class="instant-section"><div class="instant-section-head"><b>DNS Sonuçları</b></div><div class="tag-list">${r.dns_addresses.map(x=>`<span>${esc(x)}</span>`).join('')}</div></section>`:'';
  const error=r.error?`<section class="instant-section error-box"><b>Sonuç / Açıklama</b><p>${esc(r.error)}</p>${r.server_reachable!=null?`<small>Sunucu ping: ${r.server_reachable?'başarılı':'başarısız'}</small>`:''}</section>`:'';
  return `<div class="instant-result-head"><div><span class="status-dot status-${status}"></span><div><b>${esc(r.target||'-')}</b><small>${esc(r.test_type||'-')} · ${esc(r.effective_url||r.host||'')}</small></div></div><span class="badge ${statusClass}">${esc(status)}</span></div><div class="instant-kpis">${cards}</div>${instantVisual(r)}${error}${certHtml}${tlsHtml}${headerHtml}${dbHtml}<div class="instant-result-actions"><button class="mini-btn" id="instantExportJson">JSON</button><button class="mini-btn" id="instantExportHtml">HTML</button><button class="mini-btn" id="instantExportTxt">TXT</button><button class="btn primary" id="instantExportPdf">PDF</button></div><details class="raw-result"><summary>Detaylı teknik sonuç</summary><div class="raw-result-box"><pre>${esc(JSON.stringify(r,null,2))}</pre></div></details>`;
}
async function exportInstantResult(result,kind,button){if(!result)return;const old=button?.textContent;if(button){button.disabled=true;button.textContent='Hazırlanıyor...'}try{const token=localStorage.getItem('sm_token');const res=await fetch('/api/instant-test/export',{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{})},body:JSON.stringify({kind,result})});if(!res.ok){let d={};try{d=await res.json()}catch{}throw new Error(d.detail||`HTTP ${res.status}`)}const blob=await res.blob();const cd=res.headers.get('Content-Disposition')||'';const match=cd.match(/filename="([^"]+)"/);const name=match?match[1]:`instant-test.${kind}`;const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000);toast(`${kind.toUpperCase()} export hazırlandı`)}catch(e){toast(e.message)}finally{if(button){button.disabled=false;button.textContent=old}}}
async function instantTest(){
  const form=$('#instantTestForm');if(!form)return;const type=form.test_type,dyn=$('#instantDynamicFields'),button=form.querySelector('.instant-run-btn');let lastResult=null;
  const sync=()=>{let t=type.value;const target=form.target.value.trim();const isIp=/^(?:\d{1,3}\.){3}\d{1,3}$/.test(target)||/^\[?[0-9a-f:]+\]?$/i.test(target);if(t==='auto'&&!target)t='auto';if(isIp&&['web','headers'].includes(t))type.value='ping';dyn.innerHTML=instantFieldHtml(type.value);if(['ping','dns'].includes(type.value)){/* no port */}else if(type.value==='auto'&&isIp){type.value='ping';dyn.innerHTML=instantFieldHtml('ping')}};
  type.onchange=sync;form.target.oninput=()=>{if(form.target.value.trim()&&!type.value)type.value='auto';sync()};$('#instantResetBtn')?.addEventListener('click',()=>{form.reset();type.value='auto';dyn.innerHTML=instantFieldHtml('auto');$('#instantResult').innerHTML='<div class="empty">Test sonucu burada gösterilecek.</div>';lastResult=null});sync();
  form.onsubmit=async e=>{e.preventDefault();if(form.dataset.busy==='1')return;form.dataset.busy='1';button.disabled=true;button.innerHTML='<span class="btn-spinner"></span> Test ediliyor...';$('#instantResult').innerHTML='<div class="loading-inline">Test çalışıyor…</div>';try{const v=Object.fromEntries(new FormData(form));const options={};['username','password','database'].forEach(k=>{if(v[k]!=null)options[k]=v[k]});if(v.tls!=null)options.tls=true;if(v.ssl!=null)options.ssl=true;const payload={target:v.target,test_type:v.test_type,port:v.port,timeout:v.timeout,expected:v.expected,username:v.username,password:v.password,database:v.database,tls:v.tls==='on',ssl:v.ssl==='on',options};const r=await api('/api/instant-test',{method:'POST',body:JSON.stringify(payload)});lastResult=r;$('#instantResult').innerHTML=renderInstantResult(r);['Json','Html','Txt','Pdf'].forEach(k=>{const b=$(`#instantExport${k}`);b?.addEventListener('click',()=>exportInstantResult(lastResult,k.toLowerCase(),b))})}catch(err){$('#instantResult').innerHTML=`<div class="error-box"><b>Test başarısız</b><p>${esc(err.message)}</p></div>`}finally{form.dataset.busy='0';button.disabled=false;button.textContent='Testi Başlat'}};
}

async function audit(){
 const st=listState.audit;try{const d=await api(`/api/audit?q=${encodeURIComponent(st.q)}&page=${st.page}&page_size=${st.pageSize}`);const rows=d.items||[];
 $('#auditTable').innerHTML=table(['Zaman','Kullanıcı','Aksiyon','Servis / Kontrol','Detay'],rows.map(x=>[notificationTime(x.time),esc(x.actor||'-'),`<span class="badge ${String(x.action||'').includes('DELETE')?'bad':String(x.action||'').includes('CREATE')?'good':'warn'}">${esc(x.action||'-')}</span>`,`<span class="audit-ref">Servis #${x.service_id||'-'} · Kontrol #${x.control_id||'-'}</span>`,`<span class="audit-detail-preview">${esc(prettyAuditDetails(x.details))}</span>`]));
 $$('#auditTable tbody tr').forEach((row,i)=>row.onclick=()=>showAuditDetail(rows[i].id));
 $('#auditPager').innerHTML=paginationHtml('audit',d);bindPager('auditPager','audit',audit)}catch(e){toast(e.message)}bindSearch('auditSearch','audit',audit);bindPageSize('auditPageSize','audit',audit)
}
function prettyAuditDetails(value){try{const x=typeof value==='string'?JSON.parse(value):value;if(!x)return '-';const keys=['control_count','target','test_type','status','http_status','latency_ms','username'];return keys.filter(k=>x[k]!==undefined).map(k=>`${k}: ${typeof x[k]==='object'?JSON.stringify(x[k]):x[k]}`).join(' · ')||JSON.stringify(x)}catch{return String(value||'-')}}
async function showAuditDetail(id){try{const d=await api(`/api/audit/${id}`);const a=d.audit,s=d.service;const related=(d.related_logs||[]).map(x=>`<div class="related-item"><b>#${x.id} · ${esc(x.level)} · ${esc(x.category)}</b><span>${esc(notificationTime(x.time))}</span><small>${esc(x.message||'-')}</small></div>`).join('');modalDetail(`Denetim #${id}`,`<div class="detail-log-hero"><span class="badge good">${esc(a.action||'İŞLEM')}</span><b>${esc(a.actor||'system')}</b><span>${esc(notificationTime(a.time))}</span></div><div class="detail-message">${esc(notificationValue(a.details||'-'))}</div><div class="form-grid"><div class="field"><label>Kullanıcı</label><input readonly value="${esc(a.actor||'-')}"></div><div class="field"><label>Aksiyon</label><input readonly value="${esc(a.action||'-')}"></div><div class="field"><label>Servis</label><input readonly value="${esc(s?`${s.name} (#${s.id})`:'Sistem')}"></div><div class="field"><label>Kontrol</label><input readonly value="${esc(a.control_id?`#${a.control_id}`:'-')}"></div><div class="field"><label>Servis tipi</label><input readonly value="${esc(s?.monitor_type||'-')}"></div><div class="field"><label>IP</label><input readonly value="${esc(s?.resolved_ip||'-')}"></div><div class="field"><label>Durum</label><input readonly value="${esc(s?.last_status||'-')}"></div></div><section class="detail-related"><h4>İlgili işlem kayıtları</h4><div class="related-list">${related||'<div class="empty">İlişkili kayıt yok.</div>'}</div></section>`)}catch(e){toast(e.message)}}
async function retention(){const d=await api('/api/settings');const r=d.retention||{};const f=$('#retentionForm');if(!f)return;f.retention_enabled.checked=!!r.retention_enabled;f.retention_checks_days.value=r.retention_checks_days||30;f.retention_logs_days.value=r.retention_logs_days||90;f.retention_audit_days.value=r.retention_audit_days||365;f.retention_incidents_days.value=r.retention_incidents_days||3650;f.retention_cleanup_hour.value=r.retention_cleanup_hour??3;f.onsubmit=async e=>{e.preventDefault();const v={retention_enabled:f.retention_enabled.checked,retention_checks_days:Math.max(1,Math.min(3650,Number(f.retention_checks_days.value)||30)),retention_logs_days:Math.max(1,Math.min(3650,Number(f.retention_logs_days.value)||90)),retention_audit_days:Math.max(1,Math.min(3650,Number(f.retention_audit_days.value)||365)),retention_incidents_days:Math.max(1,Math.min(3650,Number(f.retention_incidents_days.value)||3650)),retention_cleanup_hour:Math.max(0,Math.min(23,Number(f.retention_cleanup_hour.value)||0))};await api('/api/settings',{method:'PUT',body:JSON.stringify({app:v})});toast('Veri saklama politikası kaydedildi');retention()};$('#retentionCleanupBtn').onclick=async()=>{try{const x=await api('/api/settings/retention/cleanup',{method:'POST'});$('#retentionStatus').textContent=`Temizlendi: ${JSON.stringify(x.deleted||{})}`;toast('Retention temizliği tamamlandı')}catch(e){toast(e.message)}}}
async function settings(){
 const d=await api('/api/settings');state.settings=d;const a=d.app;
 $('#appForm').innerHTML=`<div class="field"><label>Sistem e-postası</label><input name="system_email" type="email" value="${esc(a.system_email||'')}"></div><div class="field"><label>Varsayılan bildirim grubu</label><select name="default_notification_group_id"><option value="">Seçiniz</option>${d.groups.map(g=>`<option value="${g.id}" ${a.default_notification_group_id===g.id?'selected':''}>${esc(g.name)}</option>`).join('')}</select></div><div class="field"><label>Varsayılan konu</label><input name="default_notification_subject" value="${esc(a.default_notification_subject||'')}"></div><div class="field full"><label>Varsayılan mesaj</label><textarea name="default_notification_message">${esc(a.default_notification_message||'')}</textarea></div><label class="switch"><span>Recovery bildirimi</span><input name="recovery_enabled" type="checkbox" ${a.recovery_enabled?'checked':''}><span class="track"></span></label><label class="switch"><span>Günlük özet</span><input name="daily_summary_enabled" type="checkbox" ${a.daily_summary_enabled?'checked':''}><span class="track"></span></label><div class="field"><label>Günlük özet saati</label><input name="daily_summary_time" type="time" value="${esc(a.daily_summary_time||'23:55')}"></div>
 <div class="section-box full screenshot-settings-box"><div class="panel-head"><div><b>Ekran Görüntüsü Politikası</b><small>Periyot, tetikleyici kodlar, UP/DOWN ve rutin çekimler.</small></div></div><label class="switch"><span>Screenshot motoru aktif</span><input name="screenshot_on_http_failure" type="checkbox" ${a.screenshot_on_http_failure!==false?'checked':''}><span class="track"></span></label><label class="switch"><span>Periyodik rutin</span><input name="screenshot_routine_enabled" type="checkbox" ${a.screenshot_routine_enabled!==false?'checked':''}><span class="track"></span></label><label class="switch"><span>DOWN geçişinde al</span><input name="screenshot_capture_on_down" type="checkbox" ${a.screenshot_capture_on_down!==false?'checked':''}><span class="track"></span></label><label class="switch"><span>UP geçişinde al</span><input name="screenshot_capture_on_up" type="checkbox" ${a.screenshot_capture_on_up?'checked':''}><span class="track"></span></label><div class="field"><label>Tetikleyici HTTP kodları / aralıkları</label><input name="screenshot_trigger_codes" value="${esc(a.screenshot_trigger_codes||'404,500-599')}" placeholder="404,500-599"></div><div class="field"><label>Screenshot periyodu</label><div class="period-radio-group" id="screenshotPeriodGroup"><label><input type="radio" name="screenshot_interval_unit" value="seconds"><span>Sn</span></label><label><input type="radio" name="screenshot_interval_unit" value="minutes"><span>Dk</span></label><label><input type="radio" name="screenshot_interval_unit" value="hours"><span>Saat</span></label><label><input type="radio" name="screenshot_interval_unit" value="days"><span>Gün</span></label><label><input type="radio" name="screenshot_interval_unit" value="weeks"><span>Hafta</span></label></div><div class="period-value"><input name="screenshot_interval_value" type="number" min="1" value="1"><small id="screenshotPeriodHint">-</small></div></div><div class="field"><label>Tarayıcı timeout (sn)</label><input name="screenshot_timeout_seconds" type="number" min="5" max="180" value="${a.screenshot_timeout_seconds??30}"></div><div class="field"><label>İstek sonrası bekleme (sn)</label><input name="screenshot_wait_seconds" type="number" min="0" max="300" value="${a.screenshot_wait_seconds??2}"></div><div class="field"><label>Screenshot saklama (gün)</label><input name="screenshot_retention_days" type="number" min="1" max="3650" value="${a.screenshot_retention_days??30}"></div></div>
<div class="actions full"><button class="btn primary">Genel Ayarları Kaydet</button></div>`;
 bindScreenshotPeriod(a);$('#appForm').onsubmit=saveSettings;
 const brand=document.getElementById('brandingCard');if(brand){const logo=brand.querySelector('#brandingPreview');if(logo)logo.src=a.branding_logo_url||'/static/assets/um-logo.svg';brand.querySelector('#brandingFile')?.addEventListener('change',e=>{const f=e.target.files?.[0];if(!f)return;if(f.size>2*1024*1024){toast('Logo 2 MB altında olmalıdır.');return}const reader=new FileReader();reader.onload=async()=>{try{const r=await api('/api/branding',{method:'POST',body:JSON.stringify({data_url:reader.result})});document.querySelectorAll('.brand-logo').forEach(x=>x.src=r.logo_url);document.getElementById('topBrandLogo')?.setAttribute('src',r.logo_url);if(logo)logo.src=r.logo_url;toast('Logo güncellendi')}catch(err){toast(err.message)}};reader.readAsDataURL(f)})}
 $('#dailySummaryPreviewBtn').onclick=async()=>{try{const x=await api('/api/daily-summary');$('#dailySummaryPreview').textContent=x.services.map(y=>`${y.service}: ${y.last_status} | Uptime %${y.uptime_percent} | Kontrol ${y.checks} | Ortalama ${y.avg_latency_ms} ms | Olay ${y.incidents}`).join(' · ')||'Henüz ölçüm yok.'}catch(e){toast(e.message)}}
}
async function integrations(provider='smtp'){
 const d=await api('/api/settings');const s=d.smtp;const tabs=`<div class="integration-subnav"><button class="integration-tab ${provider==='smtp'?'active':''}" data-integration-target="smtp">SMTP</button><button class="integration-tab ${provider==='telegram'?'active':''}" data-integration-target="telegram">Telegram</button><button class="integration-tab ${provider==='webhook'?'active':''}" data-integration-target="webhook">Webhook</button></div>`;
 $('#integrationContent').innerHTML=tabs+'<div id="integrationProviderContent"></div>';
 const content=$('#integrationProviderContent');
 if(provider==='smtp'){
  content.innerHTML=`<div class="panel integration-card"><div class="panel-head"><div><b>SMTP / E-posta</b><small>Relay veya SMTP AUTH yapılandırması.</small></div></div><form id="smtpForm" class="form-grid"><div class="field"><label>SMTP sunucusu</label><input name="host" value="${esc(s.host||'')}" placeholder="smtp.kurum.local"></div><div class="field"><label>Port</label><input name="port" type="number" value="${s.port||587}"></div><div class="field"><label>Gönderen e-posta</label><input name="from_email" type="email" value="${esc(s.from_email||'')}" placeholder="monitor@kurum.local"></div><div class="field"><label>SMTP modu</label><select name="mode" id="smtpMode"><option value="relay" ${s.mode==='relay'?'selected':''}>Kurumsal Relay — AUTH yok</option><option value="auth" ${s.mode!=='relay'?'selected':''}>AUTH — kullanıcı/parola</option></select></div><div id="smtpAuthFields" class="smtp-auth-fields field full"><div class="form-grid"><div class="field"><label>Kullanıcı adı</label><input name="username" value="${esc(s.username||'')}"></div><div class="field"><label>Parola</label><input name="password" type="password" placeholder="Değiştirmek için girin"></div></div></div><label class="switch"><span>STARTTLS</span><input name="use_tls" type="checkbox" ${s.use_tls?'checked':''}><span class="track"></span></label><label class="switch"><span>SSL/TLS</span><input name="use_ssl" type="checkbox" ${s.use_ssl?'checked':''}><span class="track"></span></label><div class="field"><label>HELO adı</label><input name="helo_name" value="${esc(s.helo_name||'')}"></div><div class="field full"><label>Test alıcısı</label><input name="test_recipient" type="email" value="${esc(s.test_recipient||'')}" placeholder="siz@kurum.local"></div><div class="actions full"><button type="button" class="mini-btn" id="smtpTest">Test Maili Gönder</button><button class="btn primary">SMTP Ayarlarını Kaydet</button></div><div id="smtpTestResult" class="form-status full"></div></form></div>`;
  const sync=()=>$('#smtpAuthFields')?.classList.toggle('hidden',$('#smtpMode')?.value!=='auth');$('#smtpMode').onchange=sync;sync();$('#smtpForm').onsubmit=saveSettings;$('#smtpTest').onclick=async()=>{const recipient=$('#smtpForm').elements.test_recipient.value.trim();if(!recipient){toast('Test alıcısı girin');return}const r=await api('/api/smtp/test',{method:'POST',body:JSON.stringify({recipient})});$('#smtpTestResult').textContent=r.message;toast(r.message)};
 } else await renderIntegrations('#integrationProviderContent',provider);
 $$('#integrationContent .integration-tab').forEach(b=>b.onclick=()=>integrations(b.dataset.integrationTarget));
}
function bindScreenshotPeriod(app){
  const input=app?.screenshot_interval_seconds; const group=$('#screenshotPeriodGroup'); if(!input||!group)return;
  const units={seconds:{label:'saniye',factor:1},minutes:{label:'dakika',factor:60},hours:{label:'saat',factor:3600},days:{label:'gün',factor:86400},weeks:{label:'hafta',factor:604800}};
  let seconds=Math.max(60,Number(input.value)||900);
  let unit=seconds%604800===0?'weeks':seconds%86400===0?'days':seconds%3600===0?'hours':seconds%60===0?'minutes':'seconds';
  const set=()=>{const r=group.querySelector(`input[value="${unit}"]`);if(r)r.checked=true;const value=group.parentElement.querySelector('[name="screenshot_interval_value"]');if(value)value.value=Math.max(1,Math.round(seconds/units[unit].factor));const hint=$('#screenshotPeriodHint');if(hint)hint.textContent=`Yaklaşık ${seconds.toLocaleString('tr-TR')} saniye`;};
  group.querySelectorAll('input[type=radio]').forEach(r=>r.addEventListener('change',()=>{unit=r.value;set()})); set();
}
async function saveSettings(e){e.preventDefault();const f=e.target;const submit=f.querySelector('button[type="submit"]');await runFormBusy(f,submit,async()=>{const v=Object.fromEntries(new FormData(f));const isS=f.id==='smtpForm';const bool=n=>f.elements[n]?.checked||false;if(isS){v.port=+v.port;v.use_tls=bool('use_tls');v.use_ssl=bool('use_ssl');v.auth_enabled=v.mode==='auth';}else{v.default_notification_group_id=+v.default_notification_group_id;v.recovery_enabled=bool('recovery_enabled');v.daily_summary_enabled=bool('daily_summary_enabled');v.screenshot_on_http_failure=bool('screenshot_on_http_failure');v.screenshot_routine_enabled=bool('screenshot_routine_enabled');v.screenshot_capture_on_down=bool('screenshot_capture_on_down');v.screenshot_capture_on_up=bool('screenshot_capture_on_up');v.screenshot_retention_days=Math.max(1,Number(v.screenshot_retention_days)||30);const unit=v.screenshot_interval_unit||'minutes';const value=Math.max(1,Number(v.screenshot_interval_value)||1);const factors={seconds:1,minutes:60,hours:3600,days:86400,weeks:604800};v.screenshot_interval_seconds=Math.max(1,Math.round(value*(factors[unit]||60)));delete v.screenshot_interval_unit;delete v.screenshot_interval_value;v.screenshot_timeout_seconds=Math.max(5,Number(v.screenshot_timeout_seconds)||30);v.screenshot_wait_seconds=Math.max(0,Math.min(300,Number(v.screenshot_wait_seconds)||0))}await api('/api/settings',{method:'PUT',body:JSON.stringify({[isS?'smtp':'app']:v})});toast('Ayarlar kaydedildi');isS?integrations():settings()})}
const notificationLabels={service:'Servis',security:'Güvenlik',user:'Kullanıcı',system:'Sistem'};
function notificationIcon(cat){return cat==='service'?'◉':cat==='security'?'◇':cat==='user'?'♙':'•'}
function notificationTime(v){try{const d=new Date(v),now=new Date();const same=d.getFullYear()===now.getFullYear()&&d.getMonth()===now.getMonth()&&d.getDate()===now.getDate();return same?d.toLocaleTimeString('tr-TR',{hour:'2-digit',minute:'2-digit'}):d.toLocaleString('tr-TR',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'})}catch{return String(v||'')}}
function renderNotifications(data,open=false){const panel=$('#notificationPanel'),count=$('#notificationCount');if(!panel)return;const unread=Number(data?.unread||0);count.textContent=unread>99?'99+':unread;count.classList.toggle('hidden',unread===0);state.notifications=(data?.items||[]).map(normalizeNotification);updateMonitoringNotificationBadges({services:Number(data?.services||0),incidents:Number(data?.incidents||0)});if(!open)return;const grouped={};state.notifications.filter(n=>!n.read_at).forEach(n=>(grouped[n.category]??=[]).push(n));panel.innerHTML=`<div class="notification-head"><div><b>Bildirimler</b><small>${unread} okunmamış</small></div><div class="notification-head-actions"><button class="mini-btn" id="readAllNotifications">Tümünü okundu işaretle</button><button class="mini-btn" id="allNotificationsBtn">Daha fazla</button></div></div>${Object.keys(grouped).length?Object.entries(grouped).map(([cat,items])=>`<section class="notification-group"><div class="notification-group-title">${notificationIcon(cat)} ${notificationLabels[cat]||cat}</div>${items.map(n=>`<button class="notification-item unread" data-notification-id="${n.id}" data-notification-link="${esc(n.link||'')}"><span class="notification-icon">${notificationIcon(n.category)}</span><span><b>${esc(notificationValue(n.title))}</b>${n.service_name?`<small class="notification-service-ref">Servis: ${esc(n.service_name)} · ${esc(n.monitor_type||'')}</small>`:''}<small>${esc(notificationValue(n.message))}</small><time>${esc(notificationTime(n.created_at))}</time></span></button>`).join('')}</section>`).join(''):'<div class="notification-empty">Yeni bildiriminiz yok.</div>'}`;panel.classList.remove('hidden');panel.querySelector('#readAllNotifications')?.addEventListener('click',async()=>{await api('/api/notifications/read-all',{method:'POST'});await loadNotifications(true)});panel.querySelector('#allNotificationsBtn')?.addEventListener('click',openNotificationHistory);panel.querySelectorAll('.notification-item').forEach(el=>el.onclick=async()=>{const id=el.dataset.notificationId,link=el.dataset.notificationLink;await api(`/api/notifications/${id}/read`,{method:'POST'});panel.classList.add('hidden');await loadNotifications(false);if(link?.startsWith('service-detail:')){const sid=Number(link.split(':')[1]);if(sid){sessionStorage.setItem('sm_detail_id',String(sid));loadPage('service-detail')}}else if(link==='settings'){loadPage('settings')}})}
function notificationValue(v,fallback='-'){
 if(v==null)return fallback;
 if(typeof v==='object'){
   try{return JSON.stringify(v,null,2)}catch{return fallback}
 }
 const text=String(v);
 if(text.includes('[object Object]'))return fallback;
 const trimmed=text.trim();
 if((trimmed.startsWith('{')&&trimmed.endsWith('}'))||(trimmed.startsWith('[')&&trimmed.endsWith(']'))){try{return JSON.stringify(JSON.parse(trimmed),null,2)}catch{}}
 return text;
}
function normalizeNotification(n){
 if(!n||typeof n!=='object')return {id:null,title:notificationValue(n,'Bildirim'),message:'',metadata:{}};
 const templateSubject=notificationValue(n.template_subject,'');
 const templateMessage=notificationValue(n.template_message,'');
 const title=notificationValue(n.title,'');
 const message=notificationValue(n.message,'');
 return {
  ...n,
  title:title && title!=='-' ? title : (templateSubject||'Bildirim'),
  message:message && message!=='-' ? message : (templateMessage||'Bildirim ayrıntısı mevcut değil.'),
  template_subject:templateSubject,
  template_message:templateMessage,
  service_name:notificationValue(n.service_name==='-'?null:n.service_name,''),
  monitor_type:notificationValue(n.monitor_type==='-'?null:n.monitor_type,''),
  metadata:(n.metadata&&typeof n.metadata==='object')?n.metadata:{},
 };
}
function notificationDetailHtml(n){const m=(n&&typeof n.metadata==='object'&&n.metadata)||{};if(m.restricted)return '<div class="notification-restricted">Bu bildirimin teknik ayrıntıları için <b>Anlık Test Ayrıntılarını Görüntüleme</b> yetkisi gerekir.</div>';if(!m||Object.keys(m).length===0)return '';const pairs=[['Kullanıcı',m.display_name||m.username],['Hedef',m.target],['Test',m.test_type],['Host',m.host],['Port',m.port],['Durum',m.status],['HTTP',m.http_status],['Latency',m.latency_ms!=null?`${Math.round(Number(m.latency_ms))} ms`:null],['İstemci IP',m.ip],['Export',m.export_kind?String(m.export_kind).toUpperCase():null],['Zaman',m.time?notificationTime(m.time):null]];const known=pairs.filter(x=>x[1]!=null);const extra=Object.entries(m).filter(([k])=>!['restricted','display_name','username','target','test_type','host','port','status','http_status','latency_ms','ip','export_kind','time'].includes(k));return `<div class="notification-detail-grid">${[...known,...extra.map(([k,v])=>[k.replaceAll('_',' '),notificationValue(v)])].map(x=>`<div><small>${esc(x[0])}</small><b>${esc(notificationValue(x[1]))}</b></div>`).join('')}</div>`}
function showNotificationDetail(n){
 const meta=(n&&typeof n.metadata==='object'&&n.metadata)||{};
 const metaEntries=Object.entries(meta).filter(([k])=>k!=='restricted').map(([k,v])=>`<div><small>${esc(k.replaceAll('_',' '))}</small><b>${esc(notificationValue(v))}</b></div>`).join('');
 const service=n?.service_name?`<div><small>Servis</small><b>${esc(n.service_name)}${n.monitor_type?` · ${esc(n.monitor_type)}`:''}</b></div>`:'';
 const template=(n?.template_subject||n?.template_message)?`<section class="notification-detail-section"><small>Gönderilen Bildirim Şablonu</small><div class="notification-detail-message"><b>${esc(n?.template_subject||'-')}</b>${n?.template_message?`\n\n${esc(n.template_message)}`:''}</div></section>`:'';
 const body=`<div class="notification-detail-hero"><span class="badge">${esc(n?.event_type||n?.category||'BİLDİRİM')}</span><time>${esc(notificationTime(n?.created_at))}</time></div>
 <section class="notification-detail-section"><small>Başlık</small><div class="notification-detail-message">${esc(notificationValue(n?.title,'Bildirim'))}</div></section>
 <section class="notification-detail-section"><small>Mesaj</small><div class="notification-detail-message">${esc(notificationValue(n?.message,'Bildirim ayrıntısı mevcut değil.'))}</div></section>
 ${template}
 <div class="notification-detail-grid">${service}<div><small>Kategori</small><b>${esc(n?.category||'-')}</b></div>${n?.service_id?`<div><small>Servis ID</small><b>#${n.service_id}</b></div>`:''}${metaEntries}</div>
 ${meta.restricted?'<div class="notification-restricted">Bu bildirimin teknik ayrıntıları için gerekli Anlık Test Ayrıntıları yetkisi bulunmuyor.</div>':''}
 <div class="actions">${n?.link?.startsWith('service-detail:')?`<button type="button" class="btn primary" id="notificationGoService">Servis Detayına Git</button>`:''}<button type="button" class="btn" id="notificationCloseDetail">Kapat</button></div>`;
 const m=modalDetail('Bildirim Detayı',body);
 m.querySelector('#notificationCloseDetail')?.addEventListener('click',()=>m.classList.add('hidden'));
 m.querySelector('#notificationGoService')?.addEventListener('click',async()=>{const sid=Number(String(n.link).split(':')[1]);if(n.id)await api(`/api/notifications/${n.id}/read`,{method:'POST'});m.classList.add('hidden');if(sid){sessionStorage.setItem('sm_detail_id',String(sid));loadPage('service-detail')}});
 return m;
}
async function openNotificationHistory(){
 try{
  const d=await api('/api/notifications?include_read=true&limit=300'); const items=(d.items||[]).map(normalizeNotification);
  const cats=[['all','Tümü'],['unread','Okunmamış'],['read','Okunan'],...Object.entries(notificationLabels)];
  const render=(active='all')=>{
    const filtered=items.filter(n=>active==='all'||(active==='unread'&&!n.read_at)||(active==='read'&&n.read_at)||n.category===active).map(normalizeNotification);
    const body=filtered.map(n=>`<button class="notification-history-item ${n.read_at?'read':'unread'}" data-notification-id="${n.id}" data-notification-link="${esc(n.link||'')}"><span class="notification-history-icon">${notificationIcon(n.category)}</span><span><b>${esc(notificationValue(n.title))}</b>${n.service_name?`<small class="notification-service-ref">Servis: ${esc(n.service_name)} · ${esc(n.monitor_type||'')}</small>`:''}<small>${esc(notificationValue(n.message))}</small><time>${esc(notificationTime(n.created_at))}${n.read_at?` · Okundu ${esc(notificationTime(n.read_at))}`:' · Okunmadı'}</time>${notificationDetailHtml(n)}</span><em>${n.read_at?'OKUNDU':'YENİ'}</em></button>`).join('')||'<div class="notification-empty">Bu kategoride bildirim yok.</div>';
    const tabs=cats.map(([k,label])=>`<button type="button" class="notification-category-tab ${k===active?'active':''}" data-notif-category="${k}">${label}${k==='unread'?` <b>${d.unread||0}</b>`:''}</button>`).join('');
    const m=$('#detailInfoModal'); if(!m)return;
    const area=m.querySelector('.notification-history-content'); if(area)area.innerHTML=`<div class="notification-category-tabs">${tabs}</div><div class="notification-history-scroll"><div class="notification-history-toolbar"><span>${filtered.length} kayıt</span><button class="mini-btn" id="historyReadAll">Tümünü okundu işaretle</button></div>${body}</div>`;
    m.querySelectorAll('[data-notif-category]').forEach(b=>b.onclick=()=>render(b.dataset.notifCategory));
    m.querySelector('#historyReadAll')?.addEventListener('click',async()=>{await api('/api/notifications/read-all',{method:'POST'});await openNotificationHistory()});
    m.querySelectorAll('.notification-history-item').forEach(el=>el.onclick=async()=>{const id=Number(el.dataset.notificationId);const n=items.find(x=>x.id===id);if(!n)return;await api(`/api/notifications/${id}/read`,{method:'POST'});const ix=items.findIndex(x=>x.id===id);if(ix>=0)items[ix].read_at=new Date().toISOString();render(active);showNotificationDetail(await fetchNotificationDetail(n));await loadNotifications(false)});
  };
  const m=modalDetail('Bildirim Geçmişi','<div class="notification-history-content"></div>'); render('all');
 }catch(e){toast(e.message)}
}
function applyNotificationSummary(d){const count=$('#notificationCount');if(!count)return;const unread=Number(d?.unread||0);count.textContent=unread>99?'99+':unread;count.classList.toggle('hidden',unread===0);updateMonitoringNotificationBadges({services:Number(d?.services||0),incidents:Number(d?.incidents||0)})}
let notificationOpenSeq=0;
async function loadNotifications(open=false){
  if(!open){try{applyNotificationSummary(await api('/api/notifications/summary'))}catch(e){}return}
  const panel=$('#notificationPanel');if(!panel)return;const seq=++notificationOpenSeq;
  panel.innerHTML='<div class="notification-empty">Bildirimler yükleniyor…</div>';panel.classList.remove('hidden');
  try{const d=await api('/api/notifications?limit=30&include_read=false');if(seq!==notificationOpenSeq)return;renderNotifications(d,true)}
  catch(e){if(seq!==notificationOpenSeq)return;if(String(e.message||'').includes('Oturum')){panel.classList.add('hidden');return}
    console.error('Bildirimler yüklenemedi',e);
    panel.innerHTML=`<div class="notification-empty"><b>Bildirimler yüklenemedi</b><br><small>${esc(e.message||'Sunucu yanıt vermedi')}</small><br><button type="button" class="mini-btn" id="notificationRetry">Tekrar dene</button></div>`;
    panel.querySelector('#notificationRetry')?.addEventListener('click',()=>loadNotifications(true))}
}
async function fetchNotificationDetail(n){try{return normalizeNotification(await api(`/api/notifications/${n.id}`))}catch(e){return n}}
function initNotifications(){const bell=$('#notificationBell'),panel=$('#notificationPanel');if(!bell)return;bell.onclick=async e=>{e.stopPropagation();if(panel.classList.contains('hidden'))await loadNotifications(true);else panel.classList.add('hidden')};document.addEventListener('click',e=>{if(panel&&!panel.contains(e.target)&&e.target!==bell)panel.classList.add('hidden')});loadNotifications(false)}

async function applyBranding(){try{const r=await fetch('/api/branding');const d=await r.json();const u=d.logo_url||'/static/assets/um-logo.svg';document.querySelectorAll('.brand-logo').forEach(x=>x.src=u);document.getElementById('topBrandLogo')?.setAttribute('src',u)}catch{}}
function showLogin(){document.querySelector('.app-shell').classList.add('hidden');$('#loginOverlay').classList.remove('hidden');if(!$('#loginForm').dataset.bound){$('#loginForm').onsubmit=async e=>{e.preventDefault();$('#loginError').textContent='';try{const d=await api('/api/auth/login',{method:'POST',body:JSON.stringify({username:$('#loginUsername').value,password:$('#loginPassword').value})});clearScreenshotBlobCache();localStorage.setItem('sm_token',d.access_token);state.user=d.user;$('#loginOverlay').classList.add('hidden');document.querySelector('.app-shell').classList.remove('hidden');applyRoleUI();await loadPage(location.hash.slice(1)||'dashboard');if(d.user.must_change_password)showForcedPasswordChange()}catch(err){$('#loginError').textContent=err.message}};$('#loginForm').dataset.bound='1'}}
function showForcedPasswordChange(){const o=$('#passwordChangeOverlay');o.classList.remove('hidden');$('#currentPasswordWrap').style.display=state.user?.is_initial_admin?'none':'';$('#forcedPasswordForm').onsubmit=async e=>{e.preventDefault();const n=$('#newPassword').value,n2=$('#newPassword2').value;if(n.length<6){$('#passwordChangeError').textContent='Yeni şifre en az 6 karakter olmalı.';return}if(n!==n2){$('#passwordChangeError').textContent='Yeni şifreler eşleşmiyor.';return}try{await api('/api/auth/change-password',{method:'POST',body:JSON.stringify({current_password:$('#currentPassword').value,new_password:n})});state.user.must_change_password=false;o.classList.add('hidden');toast('Şifreniz güncellendi.')}catch(err){$('#passwordChangeError').textContent=err.message}}}
function applyRoleUI(){const r=state.user?.role;const n=$('#usersNav');if(n)n.style.display=(r==='super_admin'||r==='read_only_super_admin')?'':'none';const labels={super_admin:'Super Admin',admin:'Admin',read_only_super_admin:'Super Admin Read Only',read_only_admin:'Admin Read Only',semi_admin:'Semi Admin',read_only_semi_admin:'Semi Admin Read Only'};if($('#usersNav'))$('#usersNav').style.display=(r==='super_admin'||(state.user?.permissions||[]).includes('users.view'))?'':'none';if($('#roleDefaultsBtn'))$('#roleDefaultsBtn').style.display=r==='super_admin'?'':'none';if($('#userChipName'))$('#userChipName').textContent=state.user?.display_name||state.user?.username||'-';if($('#userChipRole'))$('#userChipRole').textContent=labels[r]||r||'-';}
async function bootstrapAuth(){applyBranding();initTheme();initNotifications();try{state.user=await api('/api/auth/me');document.querySelector('.app-shell').classList.remove('hidden');applyRoleUI();await loadPage(location.hash.slice(1)||'dashboard');if(state.user.must_change_password)showForcedPasswordChange()}catch(e){showLogin()}}
$('#logoutBtn')?.addEventListener('click',async()=>{try{await fetch('/api/auth/logout',{method:'POST',credentials:'same-origin'})}catch{}localStorage.removeItem('sm_token');clearScreenshotBlobCache();location.reload()});setInterval(()=>{const d=new Date();if($('#clock'))$('#clock').textContent=d.toLocaleTimeString('tr-TR')},1000);bootstrapAuth();setInterval(refresh,10000);
window.openServicesWithStatus=openServicesWithStatus;window.downloadExport=downloadExport;window.showAuditDetail=showAuditDetail;window.showLogDetail=showLogDetail;window.showIncidentDetail=showIncidentDetail;window.openService=openService;window.editService=editService;window.openDetail=openDetail;window.deleteService=deleteService;window.openGroup=openGroup;window.deleteGroup=deleteGroup;window.saveProvider=saveProvider;window.openUser=openUser;window.deleteUser=deleteUser;window.sendVerify=sendVerify;window.notificationTemplates=notificationTemplates;

/* ========================================================================
   MULTI-CONTROL UI (v3)
   One Service contains independent MonitorControl records. Legacy service
   options are preserved and mapped to the appropriate service/control scope.
   ======================================================================== */
const MC_EVENTS=['UP','DOWN','RECOVERY','WARNING','LATENCY'];
const MC_DEFAULTS={
 UP:{subject:'UP | {{SERVICE_NAME}} | {{MONITOR_TYPE}}',message:'Servis: {{SERVICE_NAME}}\nKontrol: {{MONITOR_TYPE}}\nDurum: {{STATUS}}\nZaman: {{EVENT_TIME}}\nLatency: {{LATENCY_MS}} ms'},
 DOWN:{subject:'DOWN | {{SERVICE_NAME}} | {{MONITOR_TYPE}}',message:'Servis: {{SERVICE_NAME}}\nKontrol: {{MONITOR_TYPE}}\nDurum: {{STATUS}}\nHost: {{HOST_NAME}}\nIP: {{RESOLVED_IP}}\nLatency: {{LATENCY_MS}} ms\nNeden: {{REASON}}'},
 RECOVERY:{subject:'RECOVERY | {{SERVICE_NAME}} | {{MONITOR_TYPE}}',message:'Servis: {{SERVICE_NAME}}\nKontrol: {{MONITOR_TYPE}}\nDurum: {{STATUS}}\nZaman: {{EVENT_TIME}}\nLatency: {{LATENCY_MS}} ms\nNeden: {{REASON}}'},
 WARNING:{subject:'WARNING | {{SERVICE_NAME}} | {{MONITOR_TYPE}}',message:'Servis: {{SERVICE_NAME}}\nKontrol: {{MONITOR_TYPE}}\nDurum: {{STATUS}}\nLatency: {{LATENCY_MS}} ms\nNeden: {{REASON}}'},
 LATENCY:{subject:'LATENCY | {{SERVICE_NAME}} | {{LATENCY_MS}} ms',message:'Servis: {{SERVICE_NAME}}\nKontrol: {{MONITOR_TYPE}}\nLatency: {{LATENCY_MS}} ms\nDurum: {{STATUS}}'}
};
function mcBlank(type){
 const meta=multiControlTypesCache?.items?.[type]||{};
 const config={};(meta.fields||[]).forEach(f=>{if(f.default!==undefined)config[f.name]=f.default});
 const autoGroups=(state.groups||[]).filter(g=>g.enabled!==false&&(g.auto_add_new_services||['Güvenlik Bildirim Grubu','Sistem Bildirim Grubu'].includes(g.name))).map(g=>g.id);
 const defaultGroup=Number(mcSettingsCache?.default_notification_group_id||0);
 const initialGroups=autoGroups.length?autoGroups:((defaultGroup && (state.groups||[]).some(g=>g.id===defaultGroup&&g.enabled!==false))?[defaultGroup]:[]);
 return {id:null,name:meta.label||type,control_type:type,enabled:true,url:type==='web'?'':undefined,
  interval_seconds:30,failure_threshold:3,evaluation_window_minutes:5,status_ranges:'200-299',
  ignored_http_status_codes:'401,403',config,advanced_options:{
   certificate_monitoring:type==='web'||type==='ssl',
   certificate_alert_enabled:false,certificate_alert_days:Number(mcSettingsCache?.cert_alert_days||30),certificate_notification_group_ids:initialGroups,
   certificate_notification_subject:'Sertifika uyarısı - {{SERVICE_NAME}}',
   certificate_notification_message:'{{SERVICE_NAME}} sertifikasının süresi {{CERT_DAYS}} gün içinde doluyor. Bitiş: {{CERT_EXPIRY}}',
   ignore_cert_errors:false,content_monitoring:false,content_mode:'contains',content_keywords:[],
   header_monitoring:type==='web',tls_tracking_enabled:type==='web'||type==='ssl',tls_scan_interval_unit:'days',tls_scan_interval_value:7,sla_enabled:false,sla_target:99.9
  },
  notifications:Object.fromEntries(MC_EVENTS.map(e=>[e,{enabled:e==='RECOVERY'?mcSettingsCache?.recovery_enabled===true:false,
   subject:(mcSettingsCache?.[e.toLowerCase()+'_notification_subject']||mcSettingsCache?.default_notification_subject||MC_DEFAULTS[e]?.subject||''),
   message:(mcSettingsCache?.[e.toLowerCase()+'_notification_message']||mcSettingsCache?.default_notification_message||MC_DEFAULTS[e]?.message||''),
   group_ids:initialGroups,cooldown_minutes:0,threshold_ms:1000}]))};
}
async function mcLoadMeta(){
 if(!multiControlTypesCache)multiControlTypesCache=await api('/api/v2/control-types');
 state.groups=await api('/api/groups');
 if(!mcSettingsCache){try{mcSettingsCache=(await api('/api/settings')).app||{}}catch{mcSettingsCache={}}}
 return multiControlTypesCache
}
function mcFieldValue(f,value){return value??f.default??''}
function mcRenderField(f,value){
 const val=mcFieldValue(f,value), id=`mc_${f.name}`;
 if(f.type==='boolean')return `<label class="switch"><span>${esc(f.label)}${f.required?' *':''}</span><input data-mc-field="${esc(f.name)}" id="${id}" type="checkbox" ${val?'checked':''}><span class="track"></span></label>`;
 if(f.type==='textarea')return `<div class="field full"><label>${esc(f.label)}${f.required?' *':''}</label><textarea data-mc-field="${esc(f.name)}" rows="4" ${f.required?'required':''}>${esc(val)}</textarea></div>`;
 const type=f.type==='password'?'password':f.type==='number'?'number':f.type==='url'?'url':'text';
 const placeholder=f.name==='host'?'IP, hostname veya URL (örn. monitor.example.com)':f.placeholder||'';
 return `<div class="field"><label>${esc(f.label)}${f.required?' *':''}</label><input data-mc-field="${esc(f.name)}" type="${type}" value="${esc(val)}" placeholder="${esc(placeholder)}" ${f.required?'required':''}></div>`;
}
function mcRenderNotifications(c){
 return `<div class="section-box mc-notifications"><div class="panel-head"><div><b>Bildirim Politikaları</b><small>Her kontrolün ekipleri, olayları ve mesajları bağımsızdır.</small></div></div>`+
 MC_EVENTS.map(ev=>{
   const n=c.notifications?.[ev]||{enabled:false,subject:MC_DEFAULTS[ev]?.subject||'',message:MC_DEFAULTS[ev]?.message||'',group_ids:[],cooldown_minutes:0,threshold_ms:1000};
   const selected=(n.group_ids||[]).map(Number);
   return `<div class="notification-event-card" data-mc-event="${ev}">
    <div class="event-head"><div><b>${ev}</b>${ev==='LATENCY'?'<small class="event-help">Bu eşik yalnızca LATENCY bildirim politikasına aittir.</small>':''}</div><label class="switch compact"><span>Aktif</span><input data-mc-notify-toggle type="checkbox" ${n.enabled?'checked':''}><span class="track"></span></label></div>
    <div class="notification-event-body ${n.enabled?'':'hidden'}">
      <div class="field"><label>Bildirim grupları</label><div class="selected-notification-groups" data-mc-selected-groups>${selected.map(id=>{const g=(state.groups||[]).find(x=>x.id===id);return g?`<div class="notif-group-row" data-group-id="${g.id}"><div><b>${esc(g.name)}</b><small>${g.auto_add_new_services?'Varsayılan otomatik grup':'Seçili grup'}</small></div><button type="button" class="mini-btn danger" data-remove-group="${g.id}">Kaldır</button></div>`:''}).join('')||'<div class="muted">Henüz grup seçilmedi.</div>'}</div><button type="button" class="mini-btn add-notif-group" data-add-groups="${ev}">＋ Bildirim grubu ekle</button></div>
      <div class="field"><label>Konu</label><input data-mc-subject value="${esc(n.subject||'')}"></div>
      <div class="field full"><label>Mesaj</label><textarea data-mc-message rows="4">${esc(n.message||'')}</textarea></div>
      <div class="field"><label>Cooldown (dk)</label><input data-mc-cooldown type="number" min="0" value="${Number(n.cooldown_minutes||0)}"></div>
      ${ev==='LATENCY'?`<div class="field"><label>Latency eşiği (ms)</label><input data-mc-threshold type="number" min="1" value="${Number(n.threshold_ms||1000)}"></div>`:''}
    </div>
   </div>`}).join('')+
 `<div class="note"><b>Değişkenler:</b> {{SERVICE_NAME}}, {{MONITOR_TYPE}}, {{HOST_NAME}}, {{HOST_URL}}, {{RESOLVED_IP}}, {{PORT}}, {{STATUS}}, {{PREVIOUS_STATUS}}, {{EVENT_TYPE}}, {{EVENT_TIME}}, {{LATENCY_MS}}, {{HTTP_STATUS}}, {{REASON}}, {{ERROR_MESSAGE}}, {{UPTIME_24H}}, {{AVG_LATENCY_24H}}, {{MIN_LATENCY_24H}}, {{MAX_LATENCY_24H}}, {{CHECK_COUNT_24H}}, {{DOWNTIME_24H}}, {{INCIDENT_COUNT_24H}}, {{CERT_DAYS}}, {{CERT_EXPIRY}}</div></div>`;
}
function mcOpenGroupPicker(card, eventName){
 document.getElementById('mcGroupPicker')?.remove();
 const current=[...card.querySelectorAll(`[data-mc-event="${eventName}"] [data-group-id]`)].map(x=>Number(x.dataset.groupId));
 const p=document.createElement('div');p.id='mcGroupPicker';p.className='modal';
 p.innerHTML=`<div class="modal-card compact-picker"><div class="modal-head"><div><b>Bildirim grubu seç</b><small>Seçtikleriniz bu olay politikasına eklenir.</small></div><button class="icon-close" type="button">×</button></div><div class="field"><input id="mcGroupSearch" placeholder="Grup adı ara..."></div><div id="mcGroupPickerList" class="picker-list"></div><div class="actions"><button type="button" class="btn primary" id="mcGroupPickerDone">Tamam</button></div></div>`;
 document.body.appendChild(p);
 const list=p.querySelector('#mcGroupPickerList');const search=p.querySelector('#mcGroupSearch');
 const render=()=>{const q=(search.value||'').toLowerCase();list.innerHTML=(state.groups||[]).filter(g=>g.name.toLowerCase().includes(q)).map(g=>`<label class="picker-item"><span><b>${esc(g.name)}</b><small>${g.auto_add_new_services?'Varsayılan otomatik grup':'Bildirim grubu'}</small></span><input type="checkbox" value="${g.id}" ${current.includes(g.id)?'checked':''}></label>`).join('')||'<div class="empty">Grup bulunamadı.</div>';};
 search.oninput=render;render();p.querySelector('.icon-close').onclick=()=>p.remove();p.querySelector('#mcGroupPickerDone').onclick=()=>{const ids=[...list.querySelectorAll('input:checked')].map(x=>Number(x.value));const box=card.querySelector(`[data-mc-event="${eventName}"] [data-mc-selected-groups]`);box.innerHTML=ids.map(id=>{const g=state.groups.find(x=>x.id===id);return g?`<div class="notif-group-row" data-group-id="${g.id}"><div><b>${esc(g.name)}</b><small>${g.auto_add_new_services?'Varsayılan otomatik grup':'Seçili grup'}</small></div><button type="button" class="mini-btn danger" data-remove-group="${g.id}">Kaldır</button></div>`:''}).join('')||'<div class="muted">Henüz grup seçilmedi.</div>';box.querySelectorAll('[data-remove-group]').forEach(b=>b.onclick=()=>{b.closest('[data-group-id]')?.remove();if(!box.querySelector('[data-group-id]'))box.innerHTML='<div class="muted">Henüz grup seçilmedi.</div>'});p.remove();mcRebind(card.closest('.multi-control-list')||card.parentElement);};
}
function mcAdvanced(c,index=0){
 const type=c.control_type, a=c.advanced_options||{}, web=type==='web', cert=web||type==='ssl';
 if(!cert)return '';
 const groups=state.groups||[];
 const unit=a.tls_scan_interval_unit||'days', value=Number(a.tls_scan_interval_value||7);
 return `<div class="section-box mc-advanced-options">
  <div class="panel-head"><div><b>Gelişmiş güvenlik ayarları</b><small>SSL sertifikası, TLS güvenliği ve Web güvenlik başlıkları kontrol bazında izlenir.</small></div></div>
  <label class="switch"><span>Sertifika izleme</span><input data-mc-adv="certificate_monitoring" type="checkbox" ${a.certificate_monitoring!==false?'checked':''}><span class="track"></span></label>
  <div class="mc-conditional ${a.certificate_monitoring!==false?'open':''}" data-mc-condition="certificate">
    <label class="switch"><span>HTTPS sertifika doğrulamasını yok say</span><input data-mc-adv="ignore_cert_errors" type="checkbox" ${a.ignore_cert_errors?'checked':''}><span class="track"></span></label>
    <label class="switch"><span>Sertifika alarmı</span><input data-mc-adv="certificate_alert_enabled" type="checkbox" ${a.certificate_alert_enabled?'checked':''}><span class="track"></span></label>
    <div class="mc-conditional ${a.certificate_alert_enabled?'open':''}" data-mc-condition="certificate-alert"><div class="form-grid">
      <div class="field"><label>Sertifika kaç gün kala</label><input data-mc-adv="certificate_alert_days" type="number" min="0" value="${esc(a.certificate_alert_days??30)}"></div>
      <div class="field"><label>Sertifika bildirim grupları</label><div class="selected-notification-groups cert-group-list">${(a.certificate_notification_group_ids||[]).map(Number).map(id=>{const g=groups.find(x=>x.id===id);return g?`<span class="control-chip" data-cert-group="${g.id}">${esc(g.name)} <button type="button" data-cert-remove="${g.id}">×</button></span>`:''}).join('')||'<span class="muted">Grup seçilmedi</span>'}</div><button type="button" class="mini-btn" data-cert-group-picker>＋ Grup seç</button><select data-mc-adv="certificate_notification_group_ids" multiple hidden>${groups.map(g=>`<option value="${g.id}" ${(a.certificate_notification_group_ids||[]).map(Number).includes(g.id)?'selected':''}>${esc(g.name)}</option>`).join('')}</select></div>
      <div class="field"><label>Sertifika bildirim konusu</label><input data-mc-adv="certificate_notification_subject" value="${esc(a.certificate_notification_subject||'Sertifika uyarısı - {{SERVICE_NAME}}')}"></div>
      <div class="field full"><label>Sertifika bildirim metni</label><textarea data-mc-adv="certificate_notification_message" rows="3">${esc(a.certificate_notification_message||'{{SERVICE_NAME}} sertifikasının süresi {{CERT_DAYS}} gün içinde doluyor. Bitiş: {{CERT_EXPIRY}}')}</textarea></div>
    </div></div>
  </div>
  <div class="tls-period-box"><div><b>SSL/TLS güvenlik taraması</b><small>Python OpenSSL + cryptography ile analiz edilir; uygun hedeflerde SSL Labs grade de alınır.</small></div><label class="switch compact"><span>Takip et</span><input data-mc-adv="tls_tracking_enabled" type="checkbox" ${a.tls_tracking_enabled!==false?'checked':''}><span class="track"></span></label><div class="period-control"><input data-mc-adv="tls_scan_interval_value" type="number" min="1" max="365" value="${value}"><div class="period-radio-group compact-period">${['hours','days','weeks'].map(u=>`<label><input name="tls_scan_interval_unit_${index}" data-mc-adv="tls_scan_interval_unit" type="radio" value="${u}" ${unit===u?'checked':''}><span>${u==='hours'?'Saat':u==='days'?'Gün':'Hafta'}</span></label>`).join('')}</div></div></div>
  ${web?`<div class="auto-security-box"><div><b>HTTP Security Headers</b><small>SecurityHeaders yaklaşımındaki temel güvenlik başlıkları otomatik okunur ve puanlanır. Manuel header girişi yoktur.</small></div><span class="badge good">OTOMATİK</span></div>`:''}
  <div class="form-grid"><div class="field"><label>SLA hedefi (%)</label><input data-mc-adv="sla_target" type="number" min="0" max="100" step="0.01" value="${esc(a.sla_target??99.9)}"></div></div>
  <label class="switch"><span>SLA hesabı</span><input data-mc-adv="sla_enabled" type="checkbox" ${a.sla_enabled?'checked':''}><span class="track"></span></label>
 </div>`;
}
function mcRenderCard(c,index){
 const meta=multiControlTypesCache?.items?.[c.control_type]||{label:c.control_type,fields:[]};
 return `<article class="multi-control-card" data-mc-index="${index}" data-id="${c.id||''}" data-type="${esc(c.control_type)}">
  <div class="mc-head"><div><b>${esc(c.name||meta.label)}</b><span class="control-chip">${esc(meta.label)}</span></div><div class="mc-actions"><label class="switch compact"><span>Aktif</span><input data-mc-enabled type="checkbox" ${c.enabled!==false?'checked':''}><span class="track"></span></label><button type="button" class="icon-btn" data-mc-remove>×</button></div></div>
  <div class="form-grid mc-fields"><div class="field"><label>Kontrol adı</label><input data-mc-name value="${esc(c.name||meta.label)}"></div>
  ${meta.fields.map(f=>mcRenderField(f,c.config?.[f.name])).join('')}
  <div class="field"><label>Kontrol aralığı (sn)</label><input data-mc-interval type="number" min="5" value="${c.interval_seconds??30}"></div>
  <div class="field"><label>Ardışık hata eşiği</label><input data-mc-threshold type="number" min="1" value="${c.failure_threshold??3}"></div>
  <div class="field"><label>Değerlendirme penceresi (dk)</label><input data-mc-window type="number" min="1" value="${c.evaluation_window_minutes??5}"></div></div>
  ${mcAdvanced(c,index)}
  ${mcRenderNotifications(c)}
 </article>`;
}
function cField(card,key,fallback){
 return card.querySelector(`[data-mc-field="${key}"]`)?.value||fallback;
}
function mcReadCard(card){
 const cfg={};card.querySelectorAll('[data-mc-field]').forEach(el=>{cfg[el.dataset.mcField]=el.type==='checkbox'?el.checked:el.value});
 const advanced={};
 card.querySelectorAll('[data-mc-adv]').forEach(el=>{
   const key=el.dataset.mcAdv;
   if(el.type==='radio'){if(el.checked)advanced[key]=el.value;return}
   if(el.multiple)advanced[key]=[...el.selectedOptions].map(o=>Number(o.value));
   else if(el.type==='checkbox')advanced[key]=el.checked;
   else if(el.type==='number')advanced[key]=Number(el.value)||0;
   else advanced[key]=el.value;
 });
 if(advanced.content_keywords!==undefined)advanced.content_keywords=String(advanced.content_keywords).split(',').map(x=>x.trim()).filter(Boolean);
 if(advanced.expected_headers!==undefined){try{advanced.expected_headers=JSON.parse(advanced.expected_headers||'{}')}catch{throw new Error('Beklenen HTTP headerlar geçerli JSON olmalıdır.')} }
 const out={id:Number(card.dataset.id)||null,name:card.querySelector('[data-mc-name]').value.trim(),control_type:card.dataset.type,
  enabled:card.querySelector('[data-mc-enabled]').checked,config:cfg,
  interval_seconds:Math.max(5,Number(card.querySelector('[data-mc-interval]').value)||30),
  failure_threshold:Math.max(1,Number(card.querySelector('[data-mc-threshold]').value)||3),
  evaluation_window_minutes:Math.max(1,Number(card.querySelector('[data-mc-window]').value)||5),
  status_ranges:cField(card,'status_ranges','200-299'),
  ignored_http_status_codes:cField(card,'ignored_http_status_codes','401,403'),
  advanced_options:advanced,notifications:{}};
 MC_EVENTS.forEach(ev=>{
   const box=card.querySelector(`[data-mc-event="${ev}"]`);if(!box)return;
   const groupSelect=box.querySelector('[data-mc-groups]');
   const groupIds=groupSelect?[...groupSelect.selectedOptions].map(x=>Number(x.value)):[...box.querySelectorAll('[data-mc-selected-groups] [data-group-id]')].map(x=>Number(x.dataset.groupId));
   out.notifications[ev]={enabled:box.querySelector('[data-mc-notify-toggle]').checked,
    group_ids:groupIds,
    subject:box.querySelector('[data-mc-subject]').value,message:box.querySelector('[data-mc-message]').value,
    cooldown_minutes:Math.max(0,Number(box.querySelector('[data-mc-cooldown]').value)||0),
    threshold_ms:Math.max(1,Number(box.querySelector('[data-mc-threshold]')?.value||1000))};
 });
 if(out.control_type==='web')out.url=cfg.url||'';
 else if(out.control_type==='ping')out.url=`ping://${cfg.host||''}`;
 else out.url=String(cfg.host||'');
 return out;
}
function mcRebind(root){
 root.querySelectorAll('[data-mc-notify-toggle]').forEach(x=>x.onchange=()=>x.closest('.notification-event-card').querySelector('.notification-event-body').classList.toggle('hidden',!x.checked));
 root.querySelectorAll('[data-mc-adv]').forEach(el=>{
   el.onchange=()=>{
     const card=el.closest('.multi-control-card'), key=el.dataset.mcAdv;
     if(key==='certificate_monitoring'){
       card.querySelector('[data-mc-condition="certificate"]')?.classList.toggle('open',el.checked);
       card.querySelector('[data-mc-condition="certificate-alert"]')?.classList.toggle('open',el.checked && !!card.querySelector('[data-mc-adv="certificate_alert_enabled"]')?.checked);
     }
     if(key==='certificate_alert_enabled')card.querySelector('[data-mc-condition="certificate-alert"]')?.classList.toggle('open',el.checked && !!card.querySelector('[data-mc-adv="certificate_monitoring"]')?.checked);
     if(key==='content_monitoring')card.querySelector('[data-mc-condition="content"]')?.classList.toggle('open',el.checked);
     if(key==='header_monitoring')card.querySelector('[data-mc-condition="headers"]')?.classList.toggle('open',el.checked);
     if(key==='content_mode'){
       const label=card.querySelector('[data-mc-content-label]');if(label)label.textContent=el.value==='regex'?'Regex desenleri (virgülle)':'İçerik anahtarları (virgülle)';
     }
   };
 });
 root.querySelectorAll('.add-notif-group').forEach(b=>b.onclick=()=>mcOpenGroupPicker(b.closest('.multi-control-card'),b.dataset.addGroups));
 root.querySelectorAll('[data-remove-group]').forEach(b=>b.onclick=()=>{const box=b.closest('[data-mc-selected-groups]');b.closest('[data-group-id]')?.remove();if(box&&!box.querySelector('[data-group-id]'))box.innerHTML='<div class=\"muted\">Henüz grup seçilmedi.</div>'});
 root.querySelectorAll('[data-cert-group-picker]').forEach(b=>b.onclick=()=>{
   const card=b.closest('.multi-control-card'), select=card.querySelector('[data-mc-adv=\"certificate_notification_group_ids\"]');
   const current=[...select.selectedOptions].map(o=>Number(o.value)); const p=document.createElement('div');p.className='modal';p.id='certGroupPicker';
   p.innerHTML=`<div class=\"modal-card compact-picker\"><div class=\"modal-head\"><div><b>Sertifika bildirim grubu</b><small>Grup seçin</small></div><button type=\"button\" class=\"icon-close\">×</button></div><div class=\"field\"><input id=\"certGroupSearch\" placeholder=\"Grup adı ara...\"></div><div id=\"certGroupList\" class=\"picker-list\"></div><div class=\"actions\"><button type=\"button\" class=\"btn primary\" id=\"certGroupDone\">Tamam</button></div></div>`;
   document.body.appendChild(p);const list=p.querySelector('#certGroupList'),search=p.querySelector('#certGroupSearch');const draw=()=>{const q=search.value.toLowerCase();list.innerHTML=state.groups.filter(g=>g.name.toLowerCase().includes(q)).map(g=>`<label class=\"picker-item\"><span><b>${esc(g.name)}</b></span><input type=\"checkbox\" value=\"${g.id}\" ${current.includes(g.id)?'checked':''}></label>`).join('')||'<div class=\"empty\">Grup bulunamadı.</div>'};draw();search.oninput=draw;p.querySelector('.icon-close').onclick=()=>p.remove();p.querySelector('#certGroupDone').onclick=()=>{[...select.options].forEach(o=>o.selected=list.querySelector(`input[value=\"${o.value}\"]`)?.checked||false);const box=card.querySelector('.cert-group-list');box.innerHTML=[...select.selectedOptions].map(o=>`<span class=\"control-chip\" data-cert-group=\"${o.value}\">${esc(o.text)} <button type=\"button\" data-cert-remove=\"${o.value}\">×</button></span>`).join('')||'<span class=\"muted\">Grup seçilmedi</span>';p.remove();mcRebind(card.closest('.multi-control-list')||card.parentElement)};
 });
 root.querySelectorAll('[data-cert-remove]').forEach(b=>b.onclick=()=>{const card=b.closest('.multi-control-card'),select=card.querySelector('[data-mc-adv=\"certificate_notification_group_ids\"]');const o=select.querySelector(`option[value=\"${b.dataset.certRemove}\"]`);if(o)o.selected=false;b.closest('[data-cert-group]')?.remove()});
 root.querySelectorAll('[data-mc-remove]').forEach(x=>x.onclick=()=>{if(root.querySelectorAll('.multi-control-card').length<=1){toast('Servis en az bir kontrol içermelidir.');return}x.closest('.multi-control-card').remove()});
}
function mcParseIds(v){return String(v||'').split(',').map(x=>Number(x.trim())).filter(Number.isInteger).filter(x=>x>0)}
function mcMaintenanceValue(v){return v?new Date(v).toISOString():null}
async function openService(s={}){
 await mcLoadMeta();
 const modal=$('#serviceModal');if(!modal){toast('Servis düzenleme penceresi yüklenemedi.');return}
 modal.classList.remove('hidden');$('#serviceModalTitle').textContent=s.id?'Servisi Düzenle':'Servis Ekle';
 let draft=(s.controls||[]).map(c=>JSON.parse(JSON.stringify(c)));if(!draft.length)draft=[mcBlank('web')];
 $('#serviceForm').innerHTML=`<div class="form-grid">
   <div class="field"><label>Servis adı *</label><input id="mcServiceName" required value="${esc(s.name||'')}"></div>
   <div class="field"><label>Servis yetkilisi</label><input id="mcServiceOwner" value="${esc(s.service_authorized_name||'')}"></div>
   <div class="field full"><label>Açıklama</label><textarea id="mcServiceDescription" rows="2">${esc(s.description||'')}</textarea></div>
 </div>
 <div class="section-box"><div class="panel-head"><div><b>Servis çalışma ayarları</b><small>Eski servis aktif/bakım davranışları korunmuştur.</small></div></div>
   <label class="switch"><span>Servis aktif</span><input id="mcServiceEnabled" type="checkbox" ${s.enabled!==false?'checked':''}><span class="track"></span></label>
   <label class="switch"><span>Bakım modu</span><input id="mcMaintenance" type="checkbox" ${s.maintenance?'checked':''}><span class="track"></span></label>
   <div class="mc-conditional ${s.maintenance?'open':''}" id="mcMaintenanceBox"><div class="form-grid"><div class="field"><label>Bakım bitiş zamanı</label><input id="mcMaintenanceUntil" type="datetime-local" value="${s.maintenance_until?String(s.maintenance_until).slice(0,16):''}"></div><div class="field"><label>Bakım nedeni</label><input id="mcMaintenanceReason" value="${esc(s.maintenance_reason||'')}"></div></div></div>
   <div class="form-grid"><div class="field"><label>Bağımlı servis ID'leri (virgülle)</label><input id="mcDependencyIds" value="${esc((s.dependency_ids||[]).join(', '))}" placeholder="Örn: 12, 18"></div><label class="switch"><span>Bağımlılık bildirimleri</span><input id="mcDependencyNotifications" type="checkbox" ${s.dependency_notifications_enabled?'checked':''}><span class="track"></span></label></div>
 </div>
 <div class="section-box"><div class="panel-head"><div><b>Kontroller</b><small>＋ ile aynı servis altında Web, Ping, PostgreSQL veya başka desteklenen tipleri ekleyin.</small></div><button type="button" class="mini-btn" id="mcAdd">＋ Kontrol Tipi</button></div><div id="mcList" class="multi-control-list"></div></div>
 <div class="note">Bildirim grupları artık servis seviyesinde tek bir seçim değildir. Her kontrolün UP / DOWN / RECOVERY / WARNING / LATENCY politikası altında ayrı ayrı belirlenir.</div>`;
 const list=$('#mcList');
 const render=()=>{list.innerHTML=draft.map((c,i)=>mcRenderCard(c,i)).join('');mcRebind(list)};
 render();
 $('#mcMaintenance').onchange=e=>$('#mcMaintenanceBox').classList.toggle('open',e.target.checked);
 $('#mcAdd').onclick=()=>{
   try{
    // The editor is DOM-driven. Before re-rendering after +, snapshot every
    // existing card so values typed by the user are not lost.
    const liveCards=[...list.querySelectorAll('.multi-control-card')];
    liveCards.forEach((card,i)=>{draft[i]=mcReadCard(card)});
   }catch(err){toast(err?.message||String(err));return}
   document.getElementById('mcPicker')?.remove();const p=document.createElement('div');p.id='mcPicker';p.className='modal';
   p.innerHTML=`<div class="modal-card"><div class="modal-head"><div><b>Kontrol tipi ekle</b><small>Seçtiğiniz tip servis altında bağımsız bir kontrol olur.</small></div><button class="icon-close" type="button">×</button></div><div class="control-type-picker">${Object.entries(multiControlTypesCache.items).map(([k,v])=>`<button type="button" data-add-type="${k}"><b>${esc(v.label)}</b><small>${v.fields?.length||0} alan</small></button>`).join('')}</div></div>`;
   document.body.appendChild(p);p.querySelector('.icon-close').onclick=()=>p.remove();p.querySelectorAll('[data-add-type]').forEach(b=>b.onclick=()=>{draft.push(mcBlank(b.dataset.addType));p.remove();render()});
 };
 const serviceForm=$('#serviceForm');
 serviceForm.dataset.busy='0';
 const saveButton=$('#serviceSaveBtn');
 if(saveButton){saveButton.disabled=false;saveButton.textContent='Kaydet';saveButton.removeAttribute('data-original-text');}
 serviceForm.onsubmit=async e=>{
   e.preventDefault();if(e.currentTarget.dataset.busy==='1')return;
   const saveBtn=$('#serviceSaveBtn');
   try{
    e.currentTarget.dataset.busy='1';
    if(saveBtn){saveBtn.disabled=true;saveBtn.dataset.originalText=saveBtn.textContent;saveBtn.textContent='Kaydediliyor…'}
    const controls=[...list.querySelectorAll('.multi-control-card')].map(mcReadCard);
    const name=$('#mcServiceName').value.trim();if(!name)throw new Error('Servis adı zorunludur.');
    if(!controls.length)throw new Error('En az bir kontrol ekleyin.');
    const payload={name,description:$('#mcServiceDescription').value,service_authorized_name:$('#mcServiceOwner').value,
      enabled:$('#mcServiceEnabled').checked,maintenance:$('#mcMaintenance').checked,
      maintenance_until:$('#mcMaintenance').checked?mcMaintenanceValue($('#mcMaintenanceUntil').value):null,
      maintenance_reason:$('#mcMaintenanceReason').value,dependency_ids:mcParseIds($('#mcDependencyIds').value),
      dependency_notifications_enabled:$('#mcDependencyNotifications').checked,controls};
    const id=s.id;
    await api(id?`/api/v2/services/${id}`:'/api/v2/services',{method:id?'PUT':'POST',body:JSON.stringify(payload)});
    modal.classList.add('hidden');toast(id?'Servis güncellendi.':'Servis oluşturuldu.');if(id){sessionStorage.setItem('sm_detail_id',String(id));await serviceDetailPage()}else{listState.services.page=1;await services()};
   }catch(err){toast(err?.message||String(err))}finally{
    e.currentTarget.dataset.busy='0';
    if(saveBtn){saveBtn.disabled=false;saveBtn.textContent=saveBtn.dataset.originalText||'Kaydet'}
   }
 };
 // The action bar lives outside the dynamic form. Explicitly wire the button
 // so browsers cannot lose the form association after the form is re-rendered.

}
async function editService(id){
 try{const sid=Number(id);if(!Number.isInteger(sid)||sid<=0)throw new Error('Geçersiz servis ID.');const d=await api(`/api/v2/services/${sid}`);await openService(d.service)}
 catch(e){toast(e.message)}
}
async function deleteService(id){if(!confirm('Servis ve tüm bağlı kontrol geçmişi silinsin mi?'))return;await api(`/api/v2/services/${id}`,{method:'DELETE'});toast('Servis silindi');services()}
async function services(){
 await mcLoadMeta();const st=listState.services;
 try{
  const d=await api(`/api/v2/services?q=${encodeURIComponent(st.q||'')}&page=${st.page}&page_size=${st.pageSize}&status=${encodeURIComponent(st.status||'ALL')}&sort=${encodeURIComponent(st.sort||'name_az')}`);
  const dPage=d;
  $('#serviceResultCount').textContent=`${Number(d.total||0).toLocaleString('tr-TR')} servis`;
  $('#serviceList').innerHTML=(dPage.items||[]).map(s=>`<article class="service-manage-card"><div class="service-manage-top"><div class="service-manage-title"><span class="status-dot status-${esc(s.status)}"></span><div><b>${esc(s.name)}</b><small>${s.control_count} kontrol</small></div></div><span class="badge ${s.status==='UP'?'good':s.status==='DOWN'?'bad':s.status==='WARNING'?'warn':''}">${esc(s.status)}</span></div><div class="dashboard-service-meta service-list-meta"><div><small>Latency</small><b>${Math.round(s.controls?.reduce((m,c)=>Math.max(m,Number(c.state.latency_ms||0)),0)||0)} ms</b></div><div class="dashboard-ip"><small>IP</small>${copyIpMarkup(s.controls?.find(c=>c.state.resolved_ip)?.state.resolved_ip||'-')}</div><div><small>Kontrol</small><b>${s.control_count}</b></div></div><div class="control-state-grid">${(s.controls||[]).map(c=>`<div class="control-state-card"><div class="control-card-title"><span class="status-dot status-${esc(c.state.status)}"></span><b title="${esc(c.name)}">${esc(c.name)}</b><span class="control-chip">${esc(c.label)}</span></div><div class="metrics"><div><small>Durum</small><b>${esc(c.state.status)}</b></div><div><small>Latency</small><b>${Math.round(c.state.latency_ms||0)} ms</b></div><div><small>Hedef</small><b title="${esc(c.url||'')}">${esc(c.url||c.config?.host||'-')}</b></div></div></div>`).join('')}</div><div class="actions service-card-actions"><button type="button" class="mini-btn" data-service-detail="${s.id}">Detay</button><button type="button" class="mini-btn" data-service-edit="${s.id}">Düzenle</button><button type="button" class="mini-btn danger" data-service-delete="${s.id}">Sil</button></div></article>`).join('')||'<div class="empty">Filtreye uygun servis bulunamadı.</div>';
  $('#servicePager').innerHTML=paginationHtml('services',dPage);bindPager('servicePager','services',services);
  $$('#serviceList [data-service-detail]').forEach(b=>b.onclick=()=>openDetail(Number(b.dataset.serviceDetail)));
  $$('#serviceList [data-service-edit]').forEach(b=>b.onclick=()=>editService(Number(b.dataset.serviceEdit)));
  $$('#serviceList [data-service-delete]').forEach(b=>b.onclick=()=>deleteService(Number(b.dataset.serviceDelete)));
  $$('#serviceList [data-copy-ip]').forEach(b=>b.onclick=e=>{e.stopPropagation();copyIp(b.dataset.copyIp)});
 }catch(e){toast(e.message)}
 bindSearch('serviceSearch','services',()=>{st.page=1;services()});bindPageSize('servicePageSize','services',()=>{st.page=1;services()});
 $('#serviceSearch').value=st.q||'';$('#servicePageSize').value=String(st.pageSize||20);
 const sortEl=$('#serviceSort');
 if(sortEl){sortEl.value=st.sort||'name_az';sortEl.onchange=()=>{st.sort=sortEl.value;st.page=1;services()}}
 document.querySelectorAll('[data-service-status]').forEach(b=>{b.classList.toggle('active',b.dataset.serviceStatus===(st.status||'ALL'));b.onclick=()=>{st.status=b.dataset.serviceStatus;st.page=1;services()}});
}
function mcStatusClass(status){return status==='DOWN'?'bad':status==='WARNING'?'warn':status==='UP'?'good':''}
function mcControlDetailHtml(c,period){
 const cutoff=period==='7d'?Date.now()-7*86400000:period==='30d'?Date.now()-30*86400000:Date.now()-86400000;
 const a=c.advanced_options||{}, cert=c.certificate||{}, hs=c.header_security||{}, tls=c.tls_security||{};
 const checks=(c.checks||[]).filter(x=>!x.time||new Date(x.time).getTime()>=cutoff).slice(-120).reverse();
 const rows=checks.map((x,i)=>`<tr><td>${i+1}</td><td>${esc(x.time?new Date(x.time).toLocaleString('tr-TR'):'-')}</td><td><span class="badge ${mcStatusClass(x.status)}">${esc(x.status)}</span></td><td>${x.code??'-'}</td><td>${Math.round(x.latency||0)} ms</td><td>${x.certificate_days??'-'} gün</td><td title="${esc(x.error||'')}">${esc(x.error||'-')}</td></tr>`).join('');
 const certPanel=(c.type==='web'||c.type==='ssl')?`<div class="panel span-2"><div class="panel-head"><div><b>Sertifika</b><small>HTTPS/SSL sertifika sağlığı ve alarm ayarları</small></div><span class="badge ${cert.monitoring?'good':''}">${cert.monitoring?'İzleniyor':'Pasif'}</span></div><div class="cert-detail-grid"><div><small>Common Name</small><b>${esc(cert.subject||'-')}</b></div><div><small>Issuer</small><b>${esc(cert.issuer||'-')}</b></div><div><small>Bitiş</small><b>${esc(cert.expires_at?new Date(cert.expires_at).toLocaleString('tr-TR'):'-')}</b></div><div class="cert-remaining ${Number(cert.remaining_days)<30?'warn':''}"><small>Kalan</small><b>${cert.remaining_days??'-'} gün</b></div></div><div class="note">Alarm: ${cert.alert_enabled?'Aktif':'Pasif'} · ${cert.alert_days??30} gün kala · Gruplar: ${(cert.notification_group_ids||[]).length||0}</div></div>`:'';
 const headerPanel=(c.type==='web')?`<div class="panel span-2"><div class="panel-head"><div><b>HTTP Security Headers</b><small>SecurityHeaders yaklaşımındaki temel başlıklar otomatik okunur</small></div><span class="badge ${String(hs.grade||'').startsWith('A')?'good':hs.grade==='B'?'warn':'bad'}">${esc(hs.grade||'-')} · ${hs.score??0}/100</span></div>${(hs.checks||[]).map(x=>`<div class="security-header-row"><span class="badge ${x.status==='PASS'?'good':x.status==='NOT_APPLICABLE'?'':'bad'}">${x.status}</span><b>${esc(x.header)}</b><code>${esc(x.value||'Eksik')}</code></div>`).join('')||'<div class="empty">Header sonucu henüz yok.</div>'}</div>`:'';
 const tlsVersionClass=(v,supported)=>{const legacy=/tlsv?1\.0|tlsv?1\.1/i.test(v);const modern=/tlsv?1\.2|tlsv?1\.3/i.test(v);return supported?(legacy?'bad':'good'):(modern?'bad':'good')};const tlsVersions=Object.entries(tls.tls_versions||{}).map(([v,x])=>`<div class="tls-version"><b>${esc(v)}</b><span class="badge ${tlsVersionClass(v,!!x.supported)}">${x.supported?'Açık':'Kapalı'}</span><small title="${esc(x.cipher||'-')}">${esc(x.cipher||'-')}</small><em title="${esc(`${x.key_exchange||''} · ${x.authentication||'-'} · ${x.encryption_bits||'?'} bit`)}">${esc(x.key_exchange||'')} · ${esc(x.authentication||'-')} · ${x.encryption_bits||'?'} bit</em></div>`).join('');
 const tlsPanel=(c.type==='web'||c.type==='ssl')?`<div class="panel span-2"><div class="panel-head"><div><b>TLS / SSL Güvenlik Analizi</b><small>${esc(tls.engine||'Python OpenSSL + cryptography + SSLyze')}</small></div><div class="actions"><span class="badge ${String(tls.grade||'').startsWith('A')?'good':tls.grade==='B'?'warn':'bad'}">${esc(tls.grade||'-')} · ${tls.score??0}/100</span><button type="button" class="mini-btn" data-deep-tls="${c.id}">Derin Tara / SSL Labs</button></div></div><div class="tls-source-row"><span>Hedef: ${esc(tls.target||c.url||'-')}</span><span>${tls.ssl_labs?.available?`SSL Labs: ${esc(tls.ssl_labs.grade||'-')}`:'SSL Labs: uygun değil / bekliyor'}</span></div><p>${esc(tls.summary||'TLS taraması henüz tamamlanmadı.')}</p><div class="tls-version-grid">${tlsVersions||'<div class="empty">TLS sürüm sonucu yok.</div>'}</div>${tls.certificate?`<div class="tls-cert-meta"><span>Sertifika seri: <b>${esc(tls.certificate.serial_number||'-')}</b></span><span>İmza: <b>${esc(tls.certificate.signature_algorithm||'-')}</b></span><span>Anahtar: <b>${esc(tls.certificate.public_key_type||'-')}</b></span></div>`:''}${(tls.findings||[]).slice(0,12).map(f=>`<div class="finding ${securityFindingClass(f.severity)}"><b>${esc(f.title)}</b><span>${esc(f.detail)}</span></div>`).join('')}<div class="cert-detail-grid"><div><small>HSTS</small><b>${tls.hsts?.present?'Etkin':'Eksik / doğrulanamadı'}</b></div><div><small>HSTS max-age</small><b>${tls.hsts?.max_age_seconds??'-'} sn</b></div><div><small>includeSubDomains</small><b>${tls.hsts?.include_subdomains?'Evet':'Hayır'}</b></div><div><small>HSTS preload</small><b>${esc(tls.hsts?.browser_preload_status||'unknown')}</b></div><div><small>CAA</small><b>${tls.caa?.records?.length?`${tls.caa.records.length} kayıt`:'Kayıt yok / doğrulanamadı'}</b></div><div><small>PCI-DSS</small><b>${tls.pci_dss_compliant?'Eski TLS yok':'Uyumsuz: TLS 1.0/1.1'}</b></div><div><small>TLS 1.3</small><b>${tls.post_quantum_readiness?.tls13_supported?'Destekleniyor':'Yok'}</b></div><div><small>Post-Quantum</small><b>${esc(tls.post_quantum_readiness?.post_quantum_key_exchange||'not_verified')}</b></div></div>${(tls.cipher_suites||[]).length?`<details><summary>Cipher Suite listesi</summary><div class="related-list">${tls.cipher_suites.map(x=>`<div class="related-item"><b>${esc(x.name)}</b><span>${esc(x.protocol||'-')} · ${esc(x.security||'-')} · ${x.bits??'-'} bit</span></div>`).join('')}</div></details>`:''}<details><summary>Zafiyet kontrolleri</summary><pre class="code-preview">${esc(JSON.stringify(tls.vulnerabilities||{},null,2))}</pre></details><details><summary>Sertifika zinciri / JSON</summary><pre class="code-preview">${esc(JSON.stringify({chain:tls.certificate_chain||{},raw:tls},null,2))}</pre></details></div>`:'';
 const shots=(c.screenshots||[]).length?`<div class="panel span-2"><div class="panel-head"><div><b>Ekran Görüntüleri</b><small>Bu servise ait periyodik, UP/DOWN ve hata tetiklemeli kayıtlar</small></div></div><div class="screenshot-grid horizontal-screenshots">${c.screenshots.map(x=>`<a href="#" data-secure-screenshot="${esc(x.path)}" target="_blank"><img src="" data-secure-screenshot="${esc(x.path)}" loading="lazy" alt="${esc(c.name)}"><div><b>${esc(x.status)} · HTTP ${x.http_status??'-'}</b><small>${esc(x.captured_at?new Date(x.captured_at).toLocaleString('tr-TR'):'-')} · ${esc(x.reason||'Periyodik')}</small></div></a>`).join('')}</div></div>`:'';
 const incidents=(c.incidents||[]).map(i=>`<p><span class="badge ${i.status==='OPEN'?'bad':'good'}">${esc(i.status)}</span> ${esc(i.reason||'-')} · ${esc(i.started?new Date(i.started).toLocaleString('tr-TR'):'')}</p>`).join('')||'<div class="empty">Olay yok.</div>';
 const configJson=JSON.stringify(c.config||{},null,2);
 const advancedJson=JSON.stringify(c.advanced_options||{},null,2);
 const controlSettings=`<div class="panel control-settings-panel"><div class="panel-head"><div><b>Kontrol Ayarları ve Hedef Bilgileri</b><small>Bu kontrolün hangi hedefi, hangi aralık ve kurallarla izlediği.</small></div></div><div class="control-settings-grid"><div><small>Hedef / URL</small><b>${esc(c.url||c.config?.host||'-')}</b></div><div><small>Çözümlenen IP</small><b>${esc(c.state.resolved_ip||'-')}</b></div><div><small>Kontrol aralığı</small><b>${c.interval_seconds??'-'} sn</b></div><div><small>Ardışık hata eşiği</small><b>${c.failure_threshold??'-'}</b></div><div><small>Değerlendirme penceresi</small><b>${c.evaluation_window_minutes??'-'} dk</b></div><div><small>UP HTTP aralığı</small><b>${esc(c.status_ranges||'-')}</b></div><div><small>İstisna HTTP kodları</small><b>${esc(c.ignored_http_status_codes||'-')}</b></div><div><small>Kontrol tipi</small><b>${esc(c.label||c.control_type||'-')}</b></div></div><details class="control-json-details"><summary>Ham kontrol ayarlarını görüntüle</summary><div class="control-json-grid"><div><h4>Config</h4><pre class="code-preview">${esc(configJson)}</pre></div><div><h4>Gelişmiş / TLS / Security</h4><pre class="code-preview">${esc(advancedJson)}</pre></div></div></details></div>`;
 return `<section class="detail-control-section"><div class="panel control-detail-hero"><div class="panel-head"><div><b>${esc(c.name)}</b><small>${esc(c.label)} · ${esc(c.url||c.config?.host||'-')}</small></div><span class="badge ${mcStatusClass(c.state.status)}">${esc(c.state.status)}</span></div><div class="detail-control-kpis"><div><small>Durum</small><strong><span class="status-dot status-${esc(c.state.status)}"></span>${esc(c.state.status)}</strong></div><div><small>Latency</small><strong>${Math.round(c.state.latency_ms||0)} ms</strong></div><div><small>Son kontrol</small><strong>${c.state.last_check_at?new Date(c.state.last_check_at).toLocaleString('tr-TR'):'-'}</strong></div><div><small>IP</small><div>${copyIpMarkup(c.state.resolved_ip)}</div></div><div><small>HTTP</small><strong>${c.state.http_status??'-'}</strong></div></div></div>${controlSettings}
 <div class="analytics-grid"><div class="panel span-2"><div class="panel-head"><div><b>Erişilebilirlik</b><small>Bu kontrolün son ölçümleri</small></div></div><div id="mcUptime_${c.id}" class="svg-chart"></div></div><div class="panel"><div class="panel-head"><div><b>Latency</b><small>Ortalama / maksimum</small></div></div><div id="mcLatency_${c.id}" class="svg-chart"></div></div><div class="panel"><div class="panel-head"><div><b>Olaylar</b><small>Bu kontrolün kesinti geçmişi</small></div></div><div id="mcIncidents_${c.id}" class="chart-summary">${incidents}</div></div>${certPanel}${headerPanel}${tlsPanel}${shots}</div>
 <div class="panel"><div class="panel-head"><div><b>Kontrol Verileri</b><small>Son ${checks.length} kayıt</small></div></div><div class="table-wrap"><table class="data-table"><thead><tr><th>#</th><th>Zaman</th><th>Durum</th><th>HTTP</th><th>Latency</th><th>Sertifika</th><th>Hata</th></tr></thead><tbody>${rows||'<tr><td colspan="7">Veri yok</td></tr>'}</tbody></table></div></div>
 <div class="panel"><div class="panel-head"><div><b>Bildirim Politikaları</b><small>Bu kontrolün aktif/pasif event politikaları</small></div></div><div class="control-policy-summary">${Object.entries(c.notifications||{}).map(([ev,n])=>`<div><span class="badge ${n.enabled?'good':''}">${ev}</span><span>${n.enabled?'Aktif':'Pasif'}</span><small>${(n.group_ids||[]).length} grup</small></div>`).join('')}</div></div></section>`;
}
async function previewService(id,service){
 let modal=document.getElementById('mcPreviewModal'); if(modal)modal.remove();
 const controls=service.controls||[]; modal=document.createElement('div');modal.id='mcPreviewModal';modal.className='modal';
 modal.innerHTML=`<div class="modal-card xwide preview-modal-card"><div class="modal-head"><div><b>Servis Önizleme / Canlı Test</b><small>${esc(service.name)} · ${controls.length} kontrol</small></div><button class="icon-close" type="button">×</button></div><div class="preview-control-list">${controls.map(c=>{const isWeb=c.control_type==='web',isPing=c.control_type==='ping';return `<div class="panel preview-control-row" data-preview-control="${c.id}"><div class="panel-head"><div><b>${esc(c.name)}</b><small>${esc(c.label)} · ${esc(c.url||c.config?.host||'-')}</small></div><span class="badge ${mcStatusClass(c.state.status)}">${esc(c.state.status)}</span></div><div class="preview-result"><span>Son latency: ${Math.round(c.state.latency_ms||0)} ms</span><span>IP: ${copyIpMarkup(c.state.resolved_ip)}</span></div><div class="preview-actions">${isWeb?`<button type="button" class="mini-btn" data-preview-frame="${c.id}">Web'i önizle</button><button type="button" class="mini-btn" data-preview-open="${c.id}">Yeni sekmede aç</button>`:''}${isPing?`<button type="button" class="mini-btn" data-preview-terminal="${c.id}">Ping terminali</button>`:''}<button type="button" class="mini-btn primary" data-preview-run="${c.id}">Canlı Test</button></div><div class="preview-extra" data-preview-extra="${c.id}"></div></div>`}).join('')||'<div class="empty">Kontrol yok.</div>'}</div></div>`;
 document.body.appendChild(modal); modal.querySelector('.icon-close').onclick=()=>modal.remove(); modal.addEventListener('click',e=>{if(e.target===modal)modal.remove()});
 modal.querySelectorAll('[data-copy-ip]').forEach(b=>b.onclick=()=>copyIp(b.dataset.copyIp));
 modal.querySelectorAll('[data-preview-frame]').forEach(btn=>btn.onclick=()=>{const c=controls.find(x=>x.id===Number(btn.dataset.previewFrame));const extra=modal.querySelector(`[data-preview-extra="${c.id}"]`);const url=c?.url||'';extra.innerHTML=`<div class="preview-web-frame"><div class="preview-frame-note"><span>Iframe güvenlik politikası nedeniyle boş kalabilir.</span><button type="button" class="mini-btn" data-preview-frame-open="1">Yeni sekmede aç</button></div><iframe src="${esc(url)}" loading="lazy" referrerpolicy="no-referrer"></iframe></div>`;extra.querySelector('[data-preview-frame-open]')?.addEventListener('click',()=>window.open(url,'_blank','noopener,noreferrer'))});
 modal.querySelectorAll('[data-preview-open]').forEach(btn=>btn.onclick=()=>{const c=controls.find(x=>x.id===Number(btn.dataset.previewOpen));if(c?.url)window.open(c.url,'_blank','noopener,noreferrer')});
 modal.querySelectorAll('[data-preview-terminal]').forEach(btn=>btn.onclick=()=>{const c=controls.find(x=>x.id===Number(btn.dataset.previewTerminal));const extra=modal.querySelector(`[data-preview-extra="${c.id}"]`);extra.innerHTML=`<div class="fake-terminal"><div class="terminal-head"><span>● Ping / ICMP</span><span>salt okunur</span></div><pre data-terminal-output>Bağlantı hazırlanıyor…</pre></div>`;runPreviewTerminal(id,c.id,extra.querySelector('[data-terminal-output]'))});
 modal.querySelectorAll('[data-preview-run]').forEach(btn=>btn.onclick=async()=>{const cid=Number(btn.dataset.previewRun),row=btn.closest('[data-preview-control]');btn.disabled=true;btn.textContent='Test ediliyor...';try{const r=await api(`/api/v2/services/${id}/controls/${cid}/preview`);row.querySelector('.preview-result').innerHTML=`<span>Durum: <b>${esc(r.status)}</b></span><span>Latency: <b>${Math.round(r.latency_ms||0)} ms</b></span><span>IP: ${copyIpMarkup(r.resolved_ip||'-')}</span><span>Hata: ${esc(r.error||'-')}</span>`;row.querySelector('.badge').textContent=r.status;row.querySelector('.badge').className=`badge ${mcStatusClass(r.status)}`;row.querySelectorAll('[data-copy-ip]').forEach(b=>b.onclick=()=>copyIp(b.dataset.copyIp));}catch(e){toast(e.message)}finally{btn.disabled=false;btn.textContent='Canlı Test'}});
}
async function runPreviewTerminal(sid,cid,output){try{const r=await api(`/api/v2/services/${sid}/controls/${cid}/preview`);const target=r.host||r.resolved_ip||'hedef';output.textContent=`$ ping ${target}\n\nDurum   : ${r.status}\nHedef   : ${target}\nIP      : ${r.resolved_ip||'-'}\nLatency: ${Math.round(r.latency_ms||0)} ms\nSonuç   : ${r.error||'64 bytes — erişilebilir'}`;}catch(e){output.textContent=`$ ping\n\nHATA: ${e.message}`}}
async function serviceDetailPage(){
 const id=Number(sessionStorage.getItem('sm_detail_id')||0);if(!id){$('#serviceDetailPage').innerHTML='<div class="empty">Servis seçilmedi.</div>';return}
 rangeButtons('serviceRange',()=>serviceDetailPage());
 try{
  const d=await api(`/api/v2/services/${id}/detail`),s=d.service;
  $('#serviceDetailPageTitle').textContent=s.name;
  $('#serviceDetailPageSubtitle').textContent=`${s.control_count} bağımsız kontrol · Servis durumu: ${s.status}`;
  $('#detailEditBtn').onclick=()=>editService(id);
  $('#detailPreviewBtn').style.display='';
  $('#detailPreviewBtn').onclick=()=>previewService(id,s);
  $('#serviceDetailPage').innerHTML=`<div class="detail-identity"><div class="detail-service-main"><span class="status-dot status-${esc(s.status)}"></span><div><small>İzlenen servis</small><b title="${esc(s.name)}">${esc(s.name)}</b><span>${esc(s.description||'Açıklama girilmemiş')}</span></div><span class="badge ${s.status==='UP'?'good':s.status==='DOWN'?'bad':s.status==='WARNING'?'warn':''}">${esc(s.status)}</span></div><div class="detail-owner"><small>Servis yetkilisi</small><strong>${esc(s.service_authorized_name||'-')}</strong><small>Aktif kontroller</small><strong>${s.control_count}</strong></div><div class="detail-owner detail-owner-rich"><div><small>Bakım</small><strong><span class="status-dot status-${s.maintenance?'WARNING':'UP'}"></span>${s.maintenance?'Aktif':'Pasif'}</strong></div><div><small>Bağımlılık bildirimi</small><strong>${s.dependency_notifications_enabled?'Aktif':'Pasif'}</strong></div><div><small>Son kontrol</small><strong>${esc(s.controls?.map(c=>c.state?.last_check_at).filter(Boolean).sort().reverse()[0]?notificationTime(s.controls.map(c=>c.state.last_check_at).filter(Boolean).sort().reverse()[0]):'-')}</strong></div></div></div><div class="detail-overview-strip"><div><small>Kontrol sayısı</small><b>${s.control_count}</b></div><div><small>Servis durumu</small><b><span class="status-dot status-${esc(s.status)}"></span>${esc(s.status)}</b></div><div><small>Ortalama latency</small><b>${Math.round((s.controls||[]).reduce((sum,c)=>sum+Number(c.state.latency_ms||0),0)/Math.max(1,(s.controls||[]).length))} ms</b></div><div><small>IP</small>${copyIpMarkup((s.controls||[]).find(c=>c.state.resolved_ip)?.state.resolved_ip||'-')}</div><div><small>Güvenlik</small><b>${(s.controls||[]).filter(c=>c.tls_security?.grade).length} TLS · ${(s.controls||[]).filter(c=>c.header_security?.grade).length} Header</b></div></div>
  <div class="panel"><div class="panel-head"><div><b>Kontrol Özeti</b><small>Eski detay ekranındaki sertifika, security header, TLS, screenshot, metrik, olay ve kontrol geçmişi korunarak her kontrolün altına taşındı.</small></div></div><div class="control-state-grid">${(d.controls||[]).map(c=>`<div class="control-state-card"><div class="control-card-title"><span class="status-dot status-${esc(c.state.status)}"></span><b title="${esc(c.name)}">${esc(c.name)}</b><span class="control-chip">${esc(c.label)}</span></div><div class="metrics"><div><small>Durum</small><b>${esc(c.state.status)}</b></div><div><small>Latency</small><b>${Math.round(c.state.latency_ms||0)} ms</b></div><div><small>Hedef</small><b title="${esc(c.url||c.config?.host||'')}">${esc(c.url||c.config?.host||'-')}</b></div></div></div>`).join('')}</div></div>
  ${(d.controls||[]).map(c=>mcControlDetailHtml(c,serviceDetailPeriod)).join('')}`;
  $$('#serviceDetailPage [data-copy-ip]').forEach(b=>b.onclick=()=>copyIp(b.dataset.copyIp));
  $$('#serviceDetailPage [data-deep-tls]').forEach(b=>b.onclick=async()=>{b.disabled=true;b.textContent='Taranıyor…';try{const r=await api(`/api/v2/services/${id}/controls/${b.dataset.deepTls}/tls-scan`,{method:'POST'});toast(`TLS taraması tamamlandı: ${r.tls_security?.grade||'-'}`);serviceDetailPage()}catch(e){toast(e.message)}finally{b.disabled=false;b.textContent='Derin Tara / SSL Labs'}});
  (d.controls||[]).forEach(c=>{
    const rows=(c.checks||[]).slice(-60);
    const points=rows.map(x=>({label:x.time?new Date(x.time).toLocaleString('tr-TR'):'-',latency_ms:x.latency||0,up:x.status==='UP'?1:0}));
    const upEl=$(`#mcUptime_${c.id}`),latEl=$(`#mcLatency_${c.id}`);
    if(upEl)upEl.innerHTML=svgLineChart(points,[{key:'up',label:'UP'}],{max:1,format:v=>v?'UP':'DOWN'});
    if(latEl)latEl.innerHTML=svgLineChart(points,[{key:'latency_ms',label:'Latency'}],{format:v=>`${Math.round(v)} ms`});
  });
  bindChartTooltips();
 }catch(e){toast(e.message)}
}
async function openControlMetrics(sid,cid){
 const d=await api(`/api/v2/services/${sid}/controls/${cid}/metrics?days=7&page=1&page_size=1000`);
 const rows=d.items||[];$('#controlMetricsPanel').innerHTML=`<div class="panel"><div class="panel-head"><div><b>${esc(d.control.name)} — Son 7 Gün</b><small>${d.summary.checks} kontrol · Uptime %${d.summary.checks?((d.summary.up/d.summary.checks)*100).toFixed(2):'0'}</small></div></div>${svgLineChart(rows.map(r=>({label:new Date(r.time).toLocaleString('tr-TR'),latency_ms:r.latency_ms||0})),[{key:'latency_ms',label:'Latency (ms)'}])}</div>`;
}
async function reports(){
 await mcLoadMeta();const d=await api('/api/v2/services?page=1&page_size=250');const list=$('#reportList');list.innerHTML=(d.items||[]).map(s=>`<div class="panel export-card"><div class="panel-head"><div><b>${esc(s.name)}</b><small>${s.control_count} kontrol · ${esc(s.status)}</small></div></div><div class="actions export-actions">${['html','pdf','json','xml','txt'].map(k=>`<button class="export-btn export-${k}" onclick="downloadExport('${k}',${s.id})"><span class="export-icon">${k.toUpperCase()}</span><span>.${k}</span></button>`).join('')}</div></div>`).join('')||'<div class="empty">Export edilecek servis yok.</div>';
}
async function downloadExport(kind,id='all'){
 if(id==='all'){try{const d=await api('/api/v2/services?page=1&page_size=250');const items=d.items||[];if(!items.length){toast('Export edilecek servis bulunamadı.');return}for(const item of items){await downloadExport(kind,item.id)}toast(`${items.length} servis için ${kind.toUpperCase()} raporu hazırlandı.`)}catch(e){toast(e.message)}return}
 try{const token=localStorage.getItem('sm_token');const r=await fetch(`/api/v2/reports/${id}/export/${kind}`,{headers:token?{Authorization:`Bearer ${token}`}:{}});if(!r.ok){let d={};try{d=await r.json()}catch{}throw new Error(d.detail||`HTTP ${r.status}`)}const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`uptime-monitor-weekly-${id}.${kind}`;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}catch(e){toast(e.message)}
}
async function screenshots(){
 let stateS=window._mcShotState||{page:1,pageSize:24,q:'',status:'',service_id:'',control_id:''};window._mcShotState=stateS;
 $('#screenshotsList').innerHTML='<div class="empty">Yükleniyor...</div>';
 const host=$('#screenshotsList').parentElement;
 if(!document.getElementById('mcShotToolbar'))host.insertAdjacentHTML('afterbegin',`<div id="mcShotToolbar" class="screenshot-toolbar"><input id="mcShotQ" placeholder="Servis adı, IP, hostname, URL veya neden ara..." value="${esc(stateS.q)}"><select id="mcShotService"><option value="">Tüm servisler</option></select><input id="mcShotControl" type="number" min="1" placeholder="Kontrol ID" value="${esc(stateS.control_id||'')}"><select id="mcShotStatus"><option value="">Tüm durumlar</option><option>UP</option><option>WARNING</option><option>DOWN</option></select><select id="mcShotPageSize"><option>12</option><option selected>24</option><option>48</option><option>96</option></select><button class="mini-btn" id="mcShotPrev">‹</button><span id="mcShotMeta"></span><button class="mini-btn" id="mcShotNext">›</button></div>`);
 try{const svcs=await api('/api/v2/services?page=1&page_size=250');const ss=$('#mcShotService');if(ss.options.length===1){(svcs.items||[]).forEach(x=>ss.add(new Option(x.name,String(x.id))))}ss.value=stateS.service_id||'';const params=new URLSearchParams({page:String(stateS.page),page_size:String(stateS.pageSize),q:stateS.q||'',status:stateS.status||''});if(stateS.service_id)params.set('service_id',String(Number(stateS.service_id)));if(stateS.control_id)params.set('control_id',String(Number(stateS.control_id)));const d=await api(`/api/v2/screenshots?${params.toString()}`);$('#mcShotMeta').textContent=`${d.page}/${d.pages} · ${d.total} kayıt`;$('#mcShotPrev').disabled=d.page<=1;$('#mcShotNext').disabled=d.page>=d.pages;$('#mcShotPrev').onclick=()=>{stateS.page--;screenshots()};$('#mcShotNext').onclick=()=>{stateS.page++;screenshots()};$('#mcShotQ').oninput=e=>{clearTimeout(window._shotT);window._shotT=setTimeout(()=>{stateS.q=e.target.value.slice(0,100);stateS.page=1;screenshots()},250)};ss.onchange=e=>{stateS.service_id=e.target.value;stateS.page=1;screenshots()};$('#mcShotControl').onchange=e=>{stateS.control_id=e.target.value;stateS.page=1;screenshots()};$('#mcShotStatus').value=stateS.status;$('#mcShotStatus').onchange=e=>{stateS.status=e.target.value;stateS.page=1;screenshots()};$('#mcShotPageSize').value=String(stateS.pageSize);$('#mcShotPageSize').onchange=e=>{stateS.pageSize=Number(e.target.value);stateS.page=1;screenshots()};
 $('#screenshotsList').innerHTML=(d.items||[]).map(x=>`<a class="screenshot-item" href="#" data-secure-screenshot="${esc(x.path)}" target="_blank"><img loading="lazy" src="" data-secure-screenshot="${esc(x.path)}" alt="${esc(x.service_name||'Servis')}"><div><div class="screenshot-service"><b>${esc(x.service_name||`Servis #${x.service_id||'-'}`)}</b><span>${esc(x.control_id?`Kontrol #${x.control_id}`:'')}</span></div><b>${esc(x.status)} · HTTP ${x.http_status??'-'}</b><small>${esc(notificationTime(x.captured_at))}</small><span>${esc(x.reason||'-')}</span><em>${esc(x.url||'-')}</em></div></a>`).join('')||'<div class="empty">Filtreye uygun screenshot yok.</div>';
 }catch(e){toast(e.message)}
}

async function openServicesWithStatus(status){
  listState.services.status=status||'ALL'; listState.services.page=1; await loadPage('services');
}
async function copyIp(value){
  const v=String(value||'').trim();
  if(!v||v==='-') return;
  // Clipboard API is available only in secure contexts on many browsers.
  try{
    if(navigator.clipboard && window.isSecureContext){
      await navigator.clipboard.writeText(v);
      toast(`Kopyalandı: ${v}`);
      return;
    }
  }catch(_err){ /* use the compatibility fallback below */ }
  let ta;
  try{
    ta=document.createElement('textarea');
    ta.value=v;
    ta.setAttribute('readonly','');
    ta.setAttribute('aria-hidden','true');
    ta.style.position='fixed';
    ta.style.left='-9999px';
    ta.style.top='0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0,ta.value.length);
    const copied=document.execCommand('copy');
    if(copied){toast(`Kopyalandı: ${v}`);return;}
  }catch(_err){ /* report failure below */ }
  finally{ta?.remove();}
  // Last-resort fallback: select the text so the user can copy with Ctrl+C.
  try{
    const promptValue=window.prompt('Otomatik kopyalama engellendi. IP adresini kopyalayın:',v);
    if(promptValue!==null) return;
  }catch(_err){}
  toast('IP kopyalanamadı. Tarayıcı pano iznini kontrol edin.');
}
function copyIpMarkup(value){const v=String(value||'').trim();return v&&v!=='-'?`<button type="button" class="copy-ip" data-copy-ip="${esc(v)}" title="IP adresini kopyala">${esc(v)} <span>⧉</span></button>`:'-'}
function renderDashboardBars(target,items,labelKey,valueKey,format=(v)=>v){
  if(!items.length){target.innerHTML='<div class="empty">Seçilen dönemde veri yok.</div>';return}
  const max=Math.max(1,...items.map(x=>Number(x[valueKey])||0));
  target.innerHTML=items.map(x=>`<div class="hbar-row rich" data-chart-tip="${esc(`${x[labelKey]}: ${format(Number(x[valueKey])||0)}`)}"><div class="hbar-label"><span title="${esc(x[labelKey])}">${esc(x[labelKey])}</span><small>${format(Number(x[valueKey])||0)}</small></div><div class="hbar-track"><i style="width:${Math.max(2,(Number(x[valueKey])||0)/max*100)}%"></i></div></div>`).join('');
  target.querySelectorAll('[data-chart-tip]').forEach(el=>{el.onmouseenter=()=>showDashboardTip(el);el.onmouseleave=hideDashboardTip});
}
function showDashboardTip(el){let t=document.getElementById('chartTooltip');if(!t){t=document.createElement('div');t.id='chartTooltip';t.className='chart-tooltip';document.body.appendChild(t)}t.textContent=el.dataset.chartTip;t.classList.add('show');const r=el.getBoundingClientRect();t.style.left=`${Math.min(window.innerWidth-260,Math.max(10,r.left+r.width/2))}px`;t.style.top=`${Math.max(8,r.top-38)}px`}
function hideDashboardTip(){document.getElementById('chartTooltip')?.classList.remove('show')}
async function dashboard(){
  try{
    await mcLoadMeta();
    const period=dashboardPeriod||'24h';
    const d=await api(`/api/v2/dashboard?period=${period}`);
    const sum=d.summary||{}, counts=d.status_counts||{};
    const statHtml=[['Servis',sum.services||0,'ALL'],['UP',sum.up||0,'UP'],['WARNING',sum.warning||0,'WARNING'],['DOWN',sum.down||0,'DOWN'],['Kontrol',sum.controls||0,null]].map(x=>`<button class="stat stat-clickable" ${x[2]?`data-dashboard-status="${x[2]}"`:''}><small>${x[0]}</small><strong>${Number(x[1]).toLocaleString('tr-TR')}</strong>${x[2]?'<span>Servisleri filtrele →</span>':''}</button>`).join('');
    $('#stats').innerHTML=statHtml;
    $$('#stats [data-dashboard-status]').forEach(b=>b.onclick=()=>openServicesWithStatus(b.dataset.dashboardStatus));
    const timeline=d.timeline||[];
    const lineData=timeline.map(x=>({label:x.label,uptime:x.uptime??0,avg_latency:x.avg_latency||0,max_latency:x.max_latency||0,checks:x.checks||0,up:x.up||0,down:x.down||0,warning:x.warning||0,incidents:x.incidents||0,downtime:x.downtime_seconds||0}));
    $('#uptimeChart').innerHTML=svgLineChart(lineData,[{key:'uptime',label:'Uptime %'}],{max:100,format:v=>`${Math.round(v)}%`});
    $('#latencyChart').innerHTML=svgLineChart(lineData,[{key:'avg_latency',label:'Ortalama'},{key:'max_latency',label:'Maksimum'}],{format:v=>`${Math.round(v)} ms`});
    $('#checksChart').innerHTML=svgLineChart(lineData,[{key:'up',label:'UP'},{key:'warning',label:'WARNING'},{key:'down',label:'DOWN'}],{format:v=>Math.round(v)});
    $('#incidentChart').innerHTML=svgLineChart(lineData,[{key:'incidents',label:'Olay'},{key:'downtime',label:'Downtime sn'}],{format:v=>Math.round(v)});
    renderDonut($('#statusChart'),counts);renderDashboardBars($('#typeChart'),Object.entries(d.type_counts||{}).map(([k,v])=>({type:multiControlTypesCache.items[k]?.label||k,count:v})),'type','count');
    renderDashboardBars($('#slowestChart'),d.top_latency||[],'name','latency',v=>`${Math.round(v)} ms`);
    renderDashboardBars($('#httpStatusChart'),Object.entries(d.http_status_counts||{}).map(([k,v])=>({code:k,count:v})),'code','count');
    const tlsGrades={};
    (d.tls_grades||[]).forEach(x=>tlsGrades[x.grade||'Yok']=(tlsGrades[x.grade||'Yok']||0)+1);
    renderDashboardBars($('#tlsChart'),Object.entries(tlsGrades).map(([k,v])=>({grade:k,count:v})),'grade','count');
    $('#latencyStats').textContent=`${Math.round(sum.avg_latency_ms||0)} ms ortalama · %${sum.uptime_percent||0} uptime · ${sum.checks||0} ölçüm`;
    $('#serviceCards').innerHTML=(d.featured_services||[]).map(s=>`<article class="service-card" tabindex="0" onclick="openDetail(${s.id})"><div class="title"><span class="status-dot status-${esc(s.status)}"></span><b>${esc(s.name)}</b><span class="badge ${s.status==='UP'?'good':s.status==='DOWN'?'bad':s.status==='WARNING'?'warn':''}">${esc(s.status)}</span></div><div class="dashboard-card-tags"><button type="button" class="mini-btn status-filter-chip status-filter-up" onclick="event.stopPropagation();openServicesWithStatus('UP')">UP</button><button type="button" class="mini-btn status-filter-chip status-filter-warning" onclick="event.stopPropagation();openServicesWithStatus('WARNING')">WARNING</button><button type="button" class="mini-btn status-filter-chip status-filter-down" onclick="event.stopPropagation();openServicesWithStatus('DOWN')">DOWN</button>${(s.controls||[]).map(c=>`<span class="control-chip">${esc(c.label)}</span>`).join('')}</div><div class="dashboard-service-meta"><div><small>Kontroller</small><b>${s.control_count}</b></div><div><small>Latency</small><b>${Math.round(s.last_latency_ms||0)} ms</b></div><div class="dashboard-ip"><small>IP</small>${copyIpMarkup(s.last_resolved_ip)}</div></div><div class="control-state-grid">${(s.controls||[]).slice(0,4).map(c=>`<div><span class="status-dot status-${esc(c.state.status)}"></span><b>${esc(c.name)}</b><small>${esc(c.label)} · ${esc(c.state.status)} · ${Math.round(c.state.latency_ms||0)} ms</small></div>`).join('')}</div></article>`).join('')||'<div class="empty">Henüz servis tanımlı değil.</div>';
    $('#incidentBadge').textContent=sum.down||0;
    bindChartTooltips();
    $$('#dashboardRange .range-tab').forEach(b=>{b.classList.toggle('active',b.dataset.period===period);b.onclick=()=>{dashboardPeriod=b.dataset.period;dashboard()}});
    $$('#page [data-copy-ip]').forEach(b=>b.onclick=e=>{e.stopPropagation();copyIp(b.dataset.copyIp)});
  }catch(e){toast(e.message)}
}
