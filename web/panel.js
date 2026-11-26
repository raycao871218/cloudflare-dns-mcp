const $ = id => document.getElementById(id);
const writeTypes = ['A','AAAA','CNAME','MX','TXT','SRV','CAA','NS','PTR'];
const proxiedTypes = new Set(['A','AAAA','CNAME']);
const dataTypes = new Set(['SRV','CAA']);
const providerNames = {cloudflare:'Cloudflare',godaddy:'GoDaddy'};
const godaddyWriteTypes = ['A','AAAA','CNAME','MX','TXT'];
const state = {local:false, actor:null, auditCursor:null, zones:[], domain:'', records:[], plan:null, editing:null, request:0, ready:false};

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function message(id, value = '', failure = false) {
  const node = $(id);
  node.textContent = value;
  node.hidden = !value;
  node.classList.toggle('failure', failure);
}

async function api(path, body) {
  const response = await fetch(state.local ? '/panel-api'+path : path, {
    method:body === undefined ? 'GET' : 'POST',
    headers:{'x-dns-panel':'1','content-type':'application/json'},
    body:JSON.stringify(body), redirect:'error', signal:AbortSignal.timeout(80_000)
  });
  const result = await response.json();
  if (response.status === 401 && !state.local && state.actor) {
    showLogin();
    message('login-error','登录已失效，请重新连接。',true);
  }
  if (!response.ok) throw Error(result.error ?? '请求失败');
  return result;
}

function option(select, value, label = value) {
  const item = element('option', label);
  item.value = value;
  select.append(item);
}

function renderZones() {
  const search = $('zone-search').value.toLowerCase().trim();
  const provider = $('provider-filter').value;
  const source = $('source-filter').value;
  const matches = state.zones.filter(zone=>zone.name.includes(search) && (!provider || zone.provider === provider) &&
    (!source || zone.source === source));
  const count = matches.length;
  $('zone-count').textContent = count === state.zones.length
    ? count + ' 个域名' : count + ' / ' + state.zones.length;
  $('zones').replaceChildren(...matches.map(zone=>{
    const button = element('button',zone.name,'zone');
    const provider = zone.provider ?? 'cloudflare';
    const label = zone.source === providerNames[provider]+' 默认' ? providerNames[provider]+' · 默认账号'
      : providerNames[provider]+' · '+zone.source;
    button.append(element('small',label,`zone-provider zone-provider--${provider}`));
    button.setAttribute('aria-current',String(zone.name === state.domain && zone.source === state.source));
    button.addEventListener('click',()=>selectZone(zone.name,zone.source));
    return button;
  }));
  if (!matches.length) $('zones').append(element('p','没有匹配的域名','empty'));
}

function currentWriteTypes() {
  return state.zones.find(zone=>zone.name === state.domain && zone.source === state.source)?.provider === 'godaddy' ? godaddyWriteTypes : writeTypes;
}

function recordValue(record) {
  return record.content ?? (record.data ? JSON.stringify(record.data) : '');
}

function renderRecords() {
  const keyword = $('search').value.toLowerCase().trim();
  const type = $('type-filter').value;
  const rows = state.records.filter(item=>
    (!type || type === item.type) &&
    (!keyword || [item.name,recordValue(item)].some(value=>String(value).toLowerCase().includes(keyword))));
  const zone = state.zones.find(item=>item.name === state.domain && item.source === state.source);
  const writable = zone?.status === 'active' && state.ready && state.actor?.role !== 'read';
  $('summary').textContent = zone ? state.records.length+' 条记录 · '+(zone.status==='active'?'已激活':zone.status) : '';
  $('create').disabled = !writable;
  $('refresh').disabled = !zone;
  $('records').replaceChildren(...rows.map(record=>{
    const row = element('tr');
    const kind = element('td');
    kind.append(element('span',record.type,'tag'));
    const value = (record.priority == null ? '' : record.priority+'  ') + recordValue(record);
    const controls = element('td');
    const edit = element('button','编辑');
    edit.disabled = !writable || !currentWriteTypes().includes(record.type);
    edit.addEventListener('click',()=>openEditor(record));
    const remove = element('button','删除','danger');
    remove.disabled = !writable || (zone?.provider === 'godaddy' && !godaddyWriteTypes.includes(record.type));
    remove.addEventListener('click',()=>previewDelete(record, remove));
    controls.append(edit,remove);
    row.append(kind,element('td',record.name,'name'),element('td',value,'value'),
      element('td',record.ttl === 1?'自动':String(record.ttl ?? '—')),
      element('td',proxiedTypes.has(record.type)?(record.proxied?'已开启':'仅 DNS'):'—'),controls);
    return row;
  }));
  if (!rows.length) {
    const row = element('tr');
    const cell = element('td',state.domain?'没有匹配的记录':'没有可访问的域名','empty');
    cell.colSpan = 6;
    row.append(cell);
    $('records').append(row);
  }
}

function updateFilters() {
  const selected = $('type-filter').value;
  const types = [...new Set(state.records.map(record=>record.type))].sort();
  $('type-filter').replaceChildren();
  option($('type-filter'),'','全部类型');
  for (const type of types) option($('type-filter'),type);
  $('type-filter').value = types.includes(selected) ? selected : '';
}

async function selectZone(domain, source, preserveNotice = false) {
  const version = ++state.request;
  state.domain = domain;
  state.source = source;
  state.ready = false;
  state.records = [];
  $('domain').textContent = domain || 'DNS 记录';
  renderZones();
  updateFilters();
  renderRecords();
  if (!domain) return;
  message('notice','正在读取记录…');
  $('create').disabled = true;
  try {
    const result = await api('/v1/records?'+new URLSearchParams({domain,source}));
    if (version !== state.request) return;
    state.records = result.records;
    state.ready = true;
    updateFilters();
    renderRecords();
    message('notice',preserveNotice ? '变更已应用，记录已刷新。' : '');
  } catch (error) {
    if (version !== state.request) return;
    message('notice', (preserveNotice ? '变更已应用，刷新失败。' : '读取失败。')+' '+error.message,true);
  }
}

async function showWorkspace(result, actor) {
  state.actor = actor;
  $('identity').textContent = actor.actor + ' · ' + ({read:'只读',write:'可写',admin:'管理员'}[actor.role]);
  $('identity').hidden = false;
  $('audit-open').hidden = actor.role !== 'admin';
  $('members-open').hidden = actor.role !== 'admin';
  state.zones = [...result.zones].sort((a,b)=>a.name.localeCompare(b.name));
  state.sources = result.sources;
  $('provider-filter').value = '';
  updateSources();
  $('key').value = '';
  $('login').hidden = true;
  $('panel-tabs').hidden = false;
  showTab(false);
  $('logout').hidden = false;
  $('logout').textContent = state.local ? '切换成员' : '退出';
  await selectZone(state.zones[0]?.name ?? '',state.zones[0]?.source);
  if (result.warnings?.length) message('notice',result.warnings.join(' '),true);
}

async function connectLocal() {
  if (!['localhost','127.0.0.1','[::1]'].includes(location.hostname)) return;
  const submit = $('login-form').querySelector('button');
  submit.disabled = true;
  state.local = true;
  try {
    const [zones, actor] = await Promise.all([api('/v1/zones'), api('/v1/me')]);
    await showWorkspace(zones, actor);
  } catch {
    state.local = false;
  } finally {
    submit.disabled = false;
  }
}

async function panelSession(method, key) {
  const headers = {'x-dns-panel':'1'};
  if (key !== undefined) headers.authorization = 'Bearer '+key;
  const response = await fetch('/panel-session',{method,headers,redirect:'error',signal:AbortSignal.timeout(10_000)});
  const result = await response.json();
  if (!response.ok) throw Error(result.error ?? '请求失败');
  return result;
}

async function restoreSession() {
  const submit = $('login-form').querySelector('button');
  submit.disabled = true;
  try {
    const actor = await api('/v1/me');
    await showWorkspace(await api('/v1/zones'),actor);
  } catch {
    await connectLocal();
  } finally {
    submit.disabled = false;
  }
}

$('login-form').addEventListener('submit',async event=>{
  event.preventDefault();
  const submit = event.submitter;
  submit.disabled = true;
  message('login-error');
  try {
    const actor = await panelSession('POST',$('key').value.trim());
    $('key').value = '';
    await showWorkspace(await api('/v1/zones'),actor);
  } catch (error) {
    message('login-error',error.message,true);
  } finally { submit.disabled = false; }
});

function showLogin() {
  ++state.request;
  Object.assign(state,{local:false,actor:null,zones:[],domain:'',records:[],plan:null,editing:null,ready:false});
  document.querySelectorAll('dialog[open]').forEach(dialog=>dialog.close());
  $('workspace').hidden = true;
  $('panel-tabs').hidden = true;
  $('channels').hidden = true;
  $('channel-rows').replaceChildren();
  $('logout').hidden = true;
  $('audit-open').hidden = true;
  $('members-open').hidden = true;
  clearIssued();
  $('identity').hidden = true;
  $('audit-rows').replaceChildren();
  $('login').hidden = false;
  $('key').focus();
  for (const id of ['search','zone-search']) $(id).value = '';
  $('domain').textContent = 'DNS 记录';
  updateFilters();
  renderZones();
  renderRecords();
}

$('logout').addEventListener('click',async event=>{
  const button = event.currentTarget;
  button.disabled = true;
  try {
    if (!state.local) await panelSession('DELETE');
    showLogin();
  } catch (error) {
    message('notice','退出失败。 '+error.message,true);
  } finally {
    button.disabled = false;
  }
});
$('zone-search').addEventListener('input',renderZones);
function updateSources() {
  const select = $('source-filter');
  const provider = $('provider-filter').value;
  const sources = (state.sources ?? []).filter(source=>!provider || source.provider === provider);
  select.replaceChildren();
  option(select,'','全部账号');
  for (const source of sources.sort((a,b)=>a.name.localeCompare(b.name))) {
    const validity = source.expires_on ? source.expires_on+' 到期' : source.token_validity === 'permanent' ? '永久' : '一年';
    option(select,source.name,source.name+' · '+validity);
  }
}

const dateInShanghai = new Intl.DateTimeFormat('sv-SE',{timeZone:'Asia/Shanghai',year:'numeric',month:'2-digit',day:'2-digit'});

function channelExpiry(source, today) {
  if (!source.expires_on) {
    return source.token_validity === 'permanent' ? ['永久','永久'] : ['待填写','一年，到期日待确认'];
  }
  const days = (Date.parse(source.expires_on) - Date.parse(today)) / 86400000;
  if (days < 0) return [source.expires_on,'已过期','channel-expiry--expired'];
  if (days === 0) return [source.expires_on,'今天到期','channel-expiry--soon'];
  return [source.expires_on,`剩余 ${days} 天`,days <= 30 ? 'channel-expiry--soon' : undefined];
}

function renderChannels() {
  const today = dateInShanghai.format(new Date());
  const counts = new Map();
  for (const zone of state.zones) counts.set(zone.source,(counts.get(zone.source) ?? 0)+1);
  const rows = (state.sources ?? []).map(source=>{
    const [date,remaining,style] = channelExpiry(source,today);
    const row = element('tr');
    const account = element('th',source.name);
    account.scope = 'row';
    row.append(account,element('td',providerNames[source.provider],`zone-provider--${source.provider}`),
      element('td',String(counts.get(source.name) ?? 0)),element('td',date),element('td',remaining,style));
    return row;
  });
  if (!rows.length) {
    const row = element('tr');
    const cell = element('td','暂无渠道','empty');
    cell.colSpan = 5;
    row.append(cell);
    rows.push(row);
  }
  $('channel-rows').replaceChildren(...rows);
}

function showTab(channels) {
  $('workspace').hidden = channels;
  $('channels').hidden = !channels;
  $('dns-tab').setAttribute('aria-current',channels ? 'false' : 'page');
  $('channels-tab').setAttribute('aria-current',channels ? 'page' : 'false');
  if (channels) renderChannels();
}

$('dns-tab').addEventListener('click',()=>showTab(false));
$('channels-tab').addEventListener('click',()=>showTab(true));
setInterval(()=>{
  if (!$('channels').hidden) renderChannels();
},60_000);

$('provider-filter').addEventListener('change',()=>{
  updateSources();
  renderZones();
});
$('source-filter').addEventListener('change',renderZones);
$('search').addEventListener('input',renderRecords);
$('type-filter').addEventListener('change',renderRecords);
$('refresh').addEventListener('click',()=>selectZone(state.domain,state.source));
$('create').addEventListener('click',()=>openEditor(null));
for (const button of document.querySelectorAll('[data-close]')) {
  button.addEventListener('click',()=>$(button.dataset.close).close());
}

function syncEditor() {
  const type = $('record-type').value;
  $('value-label').textContent = dataTypes.has(type) ? '记录数据（JSON）' : '记录值';
  $('priority-field').hidden = type !== 'MX';
  $('proxy-field').hidden = currentWriteTypes() === godaddyWriteTypes || !proxiedTypes.has(type);
  const proxied = !$('proxy-field').hidden && $('proxy').checked;
  $('ttl').disabled = proxied;
  if (proxied) $('ttl').value = 1;
}
$('record-type').addEventListener('change',syncEditor);
$('proxy').addEventListener('change',syncEditor);

function openEditor(record) {
  state.editing = record;
  $('editor-title').textContent = record ? '编辑 DNS 记录' : '新增 DNS 记录';
  $('record-type').replaceChildren();
  for (const type of record ? [record.type] : currentWriteTypes()) option($('record-type'),type);
  $('record-type').disabled = Boolean(record);
  $('record-name').value = record?.name ?? '';
  $('record-value').value = record ? (dataTypes.has(record.type) ? JSON.stringify(record.data ?? {},null,2) : recordValue(record)) : '';
  const isGoDaddy = currentWriteTypes() === godaddyWriteTypes;
  $('ttl').min = isGoDaddy ? 600 : 1;
  $('ttl').max = isGoDaddy ? 86400 : '';
  $('ttl').value = record?.ttl ?? (isGoDaddy ? 600 : 1);
  $('proxy').checked = record?.proxied ?? false;
  $('priority').value = record?.priority ?? 10;
  $('comment').value = record?.comment ?? '';
  $('comment').closest('label').hidden = isGoDaddy;
  syncEditor();
  message('editor-error');
  $('editor').showModal();
}

function fullName(name, domain) {
  const value = name.trim().toLowerCase();
  if (value === '@') return domain;
  if (value.endsWith('.')) return value.slice(0,-1);
  if (value === domain || value.endsWith('.'+domain)) return value;
  if (value.includes('.')) throw Error('请输入当前域名下的完整主机名，或单段主机名。');
  return value+'.'+domain;
}

function formChange() {
  const editing = state.editing;
  const type = $('record-type').value;
  const record = {name:fullName($('record-name').value,state.domain),ttl:Number($('ttl').value)};
  const value = $('record-value').value;
  if (dataTypes.has(type)) {
    record.data = JSON.parse(value);
    if (!record.data || typeof record.data !== 'object' || Array.isArray(record.data)) throw Error('记录数据需要是 JSON 对象。');
  } else {
    record.content = type === 'TXT' ? value : value.trim();
  }
  if (type === 'MX') record.priority = Number($('priority').value);
  if (!$('proxy-field').hidden) record.proxied = $('proxy').checked;
  const comment = $('comment').value.trim();
  if (comment || editing?.comment) record.comment = comment;
  if (!editing) return {domain:state.domain,source:state.source,action:'create',record:{...record,type}};
  const changed = Object.fromEntries(Object.entries(record).filter(([key,value])=>JSON.stringify(value)!==JSON.stringify(editing[key])));
  if (!Object.keys(changed).length) throw Error('还没有修改任何字段。');
  return {domain:state.domain,source:state.source,action:'update',recordId:editing.id,record:changed};
}

function openReview(plan) {
  state.plan = plan;
  const action = {create:'新增',update:'修改',delete:'删除'}[plan.action];
  $('review-title').textContent = '确认'+action+'记录';
  $('review-target').textContent = plan.domain;
  $('before').textContent = plan.before ? JSON.stringify(plan.before,null,2) : '无';
  $('after').textContent = plan.after ? JSON.stringify(plan.after,null,2) : '无';
  $('apply').textContent = '确认'+action;
  $('apply').classList.toggle('danger',plan.action==='delete');
  $('apply').disabled = false;
  message('review-error');
  $('review').showModal();
}

$('record-form').addEventListener('submit',async event=>{
  event.preventDefault();
  const button = $('preview-button');
  button.disabled = true;
  message('editor-error');
  try {
    const plan = await api('/v1/preview',formChange());
    if (!$('editor').open) return;
    $('editor').close();
    openReview(plan);
  } catch (error) { message('editor-error',error.message,true); }
  finally { button.disabled = false; }
});

async function previewDelete(record, button) {
  button.disabled = true;
  const domain = state.domain;
  const version = state.request;
  try {
    const plan = await api('/v1/preview',{domain,source:state.source,action:'delete',recordId:record.id});
    if (version === state.request && !$('review').open) openReview(plan);
  } catch (error) {
    if (version === state.request) message('notice',error.message,true);
  } finally { button.disabled = false; }
}

$('review').addEventListener('cancel',event=>{
  if ($('review').dataset.applying === 'true') event.preventDefault();
});
$('apply').addEventListener('click',async()=>{
  const plan = state.plan;
  if (!plan) return;
  const dialog = $('review');
  const cancel = dialog.querySelector('[data-close]');
  $('apply').disabled = true;
  cancel.disabled = true;
  dialog.dataset.applying = 'true';
  try {
    await api('/v1/apply',{previewId:plan.previewId});
    dialog.close();
    if (state.domain === plan.domain && state.source === plan.source) await selectZone(plan.domain,plan.source,true);
  } catch (error) {
    message('review-error',error.message+'。请关闭此窗口并刷新记录，核对后再重试。',true);
  } finally {
    cancel.disabled = false;
    dialog.dataset.applying = 'false';
    state.plan = null;
  }
});

async function loadAudit(reset) {
  const filter = $('audit-filter');
  const more = $('audit-more');
  filter.disabled = more.disabled = true;
  if (reset) {
    state.auditCursor = null;
    $('audit-rows').replaceChildren();
    more.hidden = true;
  }
  message('audit-message','正在读取操作记录…');
  try {
    const query = new URLSearchParams();
    const actor = $('audit-actor').value.trim();
    if (actor) query.set('actor',actor);
    if (state.auditCursor !== null) query.set('before_id',state.auditCursor);
    const result = await api('/v1/audit?' + query);
    for (const event of result.events) {
      const row = element('tr');
      const changes = element('details');
      changes.append(element('summary','查看'),element('pre',JSON.stringify({变更前:event.before,变更后:event.after},null,2)));
      const detail = element('td');
      detail.append(changes);
      const action = {create:'新增',update:'修改',delete:'删除'}[event.action];
      row.append(...[new Date(event.created_at).toLocaleString(),event.actor,event.channel,event.domain,action,
        event.status === 'applied' ? '已应用' : '结果待核对'].map(value=>element('td',value)),detail);
      $('audit-rows').append(row);
    }
    state.auditCursor = result.nextBeforeId;
    more.hidden = state.auditCursor === null;
    message('audit-message',$('audit-rows').children.length ? '' : '暂无操作记录。');
  } catch (error) {
    message('audit-message',error.message,true);
  } finally {
    filter.disabled = more.disabled = false;
  }
}

$('audit-open').addEventListener('click',()=>{
  $('audit').showModal();
  loadAudit(true);
});
$('audit-filter').addEventListener('click',()=>loadAudit(true));
$('audit-more').addEventListener('click',()=>loadAudit(false));
$('audit-actor').addEventListener('input',()=>{ $('audit-more').hidden = true; });

const roleNames = {read:'只读',write:'可写',admin:'管理员'};
let memberAction = null;
let memberBusy = false;

function clearIssued() {
  $('issued-token').value = '';
  $('issued-label').textContent = '';
  $('issued').hidden = true;
}

function showIssued(result) {
  $('issued-label').textContent = result.name + ' 的凭证仅显示这一次。请私下交给该成员。';
  $('issued-token').value = result.token;
  $('issued').hidden = false;
}

async function loadMembers() {
  const result = await api('/v1/members');
  $('member-rows').replaceChildren(...result.members.map(member=>{
    const row = element('tr');
    const controls = element('td');
    if (member.name !== state.actor.actor) {
      const rotate = element('button',member.revoked_at ? '重新启用并签发' : '重签凭证');
      rotate.addEventListener('click',()=>confirmMember(member,'rotate'));
      controls.append(rotate);
      if (!member.revoked_at) {
        const revoke = element('button','撤销','danger');
        revoke.addEventListener('click',()=>confirmMember(member,'revoke'));
        controls.append(revoke);
      }
    } else {
      controls.textContent = '当前登录成员';
    }
    row.append(element('td',member.name),element('td',roleNames[member.role]),
      element('td',member.revoked_at ? '已撤销' : '有效'),controls);
    return row;
  }));
}

async function updateMembers(operation) {
  if (memberBusy) return;
  memberBusy = true;
  $('member-form').querySelector('button').disabled = true;
  message('members-message');
  try {
    await operation();
    await loadMembers();
  } catch (error) {
    message('members-message',error.message,true);
  } finally {
    memberBusy = false;
    $('member-form').querySelector('button').disabled = false;
  }
}

function confirmMember(member, action) {
  if (memberBusy) return;
  memberAction = {member,action};
  const label = action === 'revoke' ? '撤销凭证' : '重新签发凭证';
  $('member-confirm-title').textContent = label;
  $('member-confirm-copy').textContent = member.name + ' 的旧凭证将立即失效。';
  $('member-confirm-apply').textContent = label;
  $('member-confirm').showModal();
}

$('members-open').addEventListener('click',()=>{
  clearIssued();
  $('member-rows').replaceChildren();
  $('members').showModal();
  updateMembers(async()=>{});
});
$('members').addEventListener('close',clearIssued);
$('members').addEventListener('cancel',event=>{ if (memberBusy) event.preventDefault(); });
$('members').querySelector('[data-close]').addEventListener('click',event=>{
  if (memberBusy) event.stopImmediatePropagation();
},true);
$('member-form').addEventListener('submit',event=>{
  event.preventDefault();
  updateMembers(async()=>{
    const result = await api('/v1/members',{name:$('member-name').value.trim(),role:$('member-role').value});
    showIssued(result);
    $('member-form').reset();
  });
});
$('member-confirm-apply').addEventListener('click',()=>{
  if (!memberAction) return;
  const {member,action} = memberAction;
  memberAction = null;
  $('member-confirm').close();
  updateMembers(async()=>{
    const result = await api('/v1/members/'+encodeURIComponent(member.name)+'/'+action,{});
    if (result.token) showIssued(result);
    else {
      clearIssued();
      message('members-message',member.name+' 的凭证已撤销。');
    }
  });
});
$('issued-copy').addEventListener('click',async()=>{
  try {
    await navigator.clipboard.writeText($('issued-token').value);
    message('members-message','凭证已复制。');
  } catch {
    $('issued-token').select();
    message('members-message','请手动复制选中的凭证。');
  }
});

restoreSession();
