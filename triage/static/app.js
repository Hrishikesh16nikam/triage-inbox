// Triage Inbox client. No framework, no build step.
// The access token lives only in memory; the refresh token is an HttpOnly
// cookie this script can't read, so an XSS bug can't steal a long-lived
// session. All text is inserted with textContent, never innerHTML.

const root = document.getElementById('root');
const state = {
  token: null,
  user: null,
  tab: 'queue',
  filters: { triage_state: '', urgency: '', intent: '', status: '' },
  items: [],
  total: 0,
  selectedId: null,
  detail: null,
  assignees: [],
  notice: null,
};

const ROLE_RANK = { viewer: 0, triager: 1, admin: 2 };
const can = (role) => state.user && ROLE_RANK[state.user.role] >= ROLE_RANK[role];

// ---- tiny DOM helper -----------------------------------------------------

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const label = (s) => (s ? s.replace(/_/g, ' ') : '');
const when = (iso) => {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
};

// ---- API -----------------------------------------------------------------

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function refreshSession() {
  const res = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'same-origin' });
  if (!res.ok) {
    state.token = null;
    state.user = null;
    return false;
  }
  const data = await res.json();
  state.token = data.access_token;
  state.user = data.user;
  return true;
}

let refreshing = null;
async function api(path, { method = 'GET', json, body, headers = {} } = {}, retry = true) {
  const opts = { method, credentials: 'same-origin', headers: { ...headers } };
  if (state.token) opts.headers.Authorization = `Bearer ${state.token}`;
  if (json !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(json);
  } else if (body !== undefined) {
    opts.body = body;
  }
  const res = await fetch(path, opts);
  if (res.status === 401 && retry) {
    refreshing ??= refreshSession().finally(() => (refreshing = null));
    if (await refreshing) return api(path, { method, json, body, headers }, false);
    render();
    throw new HttpError(401, 'Your session ended. Please sign in again.');
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new HttpError(res.status, data.error || `Request failed (${res.status})`);
  return data;
}

function notify(message, kind = 'error') {
  state.notice = { message, kind };
  render();
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => {
    state.notice = null;
    render();
  }, 5000);
}

// ---- data loading --------------------------------------------------------

async function loadItems() {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(state.filters)) if (v) params.set(k, v);
  params.set('limit', '100');
  const data = await api(`/api/items?${params}`);
  state.items = data.items;
  state.total = data.total;
  const sel = state.items.find((i) => i.id === state.selectedId);
  // Refetch the open item only when it changed: every detail read is audited.
  if (sel && state.detail && sel.updated_at !== state.detail.updated_at) await loadDetail(sel.id);
}

async function loadDetail(id) {
  state.selectedId = id;
  state.detail = await api(`/api/items/${id}`);
}

async function loadAssignees() {
  if (!can('triager')) return;
  const data = await api('/api/users');
  state.assignees = data.users.filter((u) => u.active !== false && u.role !== 'viewer');
}

// ---- actions -------------------------------------------------------------

async function signIn(e) {
  e.preventDefault();
  const form = new FormData(e.target);
  const button = e.target.querySelector('button');
  button.disabled = true;
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: form.get('username'), password: form.get('password') }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Sign-in failed');
    state.token = data.access_token;
    state.user = data.user;
    await Promise.all([loadItems(), loadAssignees()]);
    state.notice = null;
    render();
  } catch (err) {
    notify(err.message);
  } finally {
    button.disabled = false;
  }
}

async function signOut() {
  await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
  Object.assign(state, { token: null, user: null, items: [], detail: null, selectedId: null, tab: 'queue' });
  render();
}

async function upload(e) {
  const files = [...e.target.files];
  e.target.value = '';
  for (const file of files) {
    try {
      await api('/api/items', {
        method: 'POST',
        body: file,
        headers: { 'X-Filename': encodeURIComponent(file.name), 'Content-Type': 'application/octet-stream' },
      });
    } catch (err) {
      notify(`${file.name}: ${err.message}`);
    }
  }
  await loadItems();
  render();
}

async function updateItem(changes) {
  try {
    state.detail = await api(`/api/items/${state.selectedId}`, { method: 'PATCH', json: changes });
    await loadItems();
    render();
  } catch (err) {
    notify(err.message);
  }
}

// ---- views ---------------------------------------------------------------

function loginView() {
  return h('main', { class: 'login' },
    h('form', { class: 'login-card', onsubmit: signIn },
      h('h1', {}, 'Triage Inbox'),
      h('p', { class: 'muted' }, 'Voicemails and documents, transcribed, redacted and sorted by urgency.'),
      h('label', {}, 'Username', h('input', { name: 'username', autocomplete: 'username', required: true, autofocus: true })),
      h('label', {}, 'Password',
        h('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true })),
      h('button', { class: 'primary', type: 'submit' }, 'Sign in'),
      h('p', { class: 'fineprint' }, 'Demo with synthetic data only. Run python -m triage seed-demo for accounts.'),
    ),
  );
}

function topBar() {
  const tabs = [['queue', 'Queue']];
  if (can('admin')) tabs.push(['audit', 'Audit log'], ['users', 'Users']);
  return h('header', { class: 'topbar' },
    h('div', { class: 'brand' }, 'Triage Inbox'),
    h('nav', { class: 'tabs' },
      tabs.map(([id, text]) =>
        h('button', {
          class: state.tab === id ? 'tab active' : 'tab',
          'aria-current': state.tab === id ? 'page' : null,
          onclick: () => switchTab(id),
        }, text))),
    h('div', { class: 'who' },
      h('span', {}, state.user.username), h('span', { class: 'role' }, state.user.role),
      h('button', { class: 'ghost', onclick: signOut }, 'Sign out')),
  );
}

async function switchTab(id) {
  state.tab = id;
  render();
  try {
    if (id === 'audit') await renderAudit();
    if (id === 'users') await renderUsers();
  } catch (err) {
    notify(err.message);
  }
}

function filterSelect(key, options) {
  return h('label', { class: 'filter' }, label(key === 'triage_state' ? 'state' : key),
    h('select', {
      value: state.filters[key],
      onchange: async (e) => {
        state.filters[key] = e.target.value;
        await loadItems().catch((err) => notify(err.message));
        render();
      },
    }, h('option', { value: '' }, 'All'),
    options.map((o) => {
      const opt = h('option', { value: o }, label(o));
      if (state.filters[key] === o) opt.selected = true;
      return opt;
    })));
}

function queueView() {
  const toolbar = h('div', { class: 'toolbar' },
    filterSelect('triage_state', ['new', 'in_progress', 'resolved']),
    filterSelect('urgency', ['high', 'medium', 'low']),
    filterSelect('intent', ['appointment', 'billing', 'prescription', 'results', 'referral', 'complaint', 'general']),
    filterSelect('status', ['queued', 'processing', 'ready', 'failed']),
    h('span', { class: 'spacer' }),
    can('triager') &&
      h('label', { class: 'button primary' }, 'Upload',
        h('input', { type: 'file', multiple: true, accept: '.wav,.mp3,.m4a,.txt,.md', class: 'visually-hidden',
          onchange: upload })),
  );

  const list = state.items.length
    ? h('ul', { class: 'queue', role: 'list' }, state.items.map(itemRow))
    : h('div', { class: 'empty' }, 'Nothing matches these filters.');

  return h('main', { class: 'workspace' },
    h('section', { class: 'list-pane' }, toolbar,
      h('p', { class: 'count muted' }, `${state.total} item${state.total === 1 ? '' : 's'}`), list),
    h('section', { class: 'detail-pane' }, state.detail ? detailView(state.detail) : emptyDetail()),
  );
}

function itemRow(item) {
  const pending = item.status !== 'ready';
  return h('li', {},
    h('button', {
      class: `row${item.id === state.selectedId ? ' selected' : ''}`,
      onclick: async () => {
        try {
          await loadDetail(item.id);
          render();
        } catch (err) {
          notify(err.message);
        }
      },
    },
    h('span', { class: `urgency u-${pending ? 'none' : item.urgency}` }, pending ? label(item.status) : item.urgency),
    h('span', { class: 'row-main' },
      h('span', { class: 'row-title' }, pending ? item.original_name : label(item.intent)),
      h('span', { class: 'row-summary' }, pending ? (item.error || 'Waiting for the worker') : item.summary)),
    h('span', { class: 'row-meta' },
      h('span', { class: `state s-${item.triage_state}` }, label(item.triage_state)),
      h('span', { class: 'muted' }, when(item.created_at)))));
}

function emptyDetail() {
  return h('div', { class: 'empty' }, 'Select an item to read it.');
}

// Show [PHONE], [EMAIL]... as redaction bars instead of plain text.
function redactedText(text) {
  const parts = text.split(/(\[(?:PHONE|EMAIL|SSN|CARD|DATE|ID)\])/);
  return h('div', { class: 'transcript' },
    parts.map((p) => /^\[[A-Z]+\]$/.test(p)
      ? h('span', { class: 'redacted', title: 'Redacted before storage' }, p.slice(1, -1).toLowerCase())
      : p));
}

function detailView(d) {
  const ready = d.status === 'ready';
  const redactions = Object.entries(d.redactions || {});
  return h('article', { class: 'detail' },
    h('div', { class: 'detail-head' },
      h('div', {},
        h('h2', {}, ready ? label(d.intent) : d.original_name),
        h('p', { class: 'muted' }, `${d.kind === 'audio' ? 'Voicemail' : 'Document'} · ${d.original_name} · ${when(d.created_at)}`)),
      ready && h('span', { class: `urgency big u-${d.urgency}` }, `${d.urgency} urgency`)),
    !ready && h('p', { class: `callout ${d.status === 'failed' ? 'bad' : ''}` },
      d.status === 'failed' ? `Processing failed: ${d.error}` : `Status: ${label(d.status)}. This updates automatically.`),
    ready && h('dl', { class: 'facts' },
      h('div', {}, h('dt', {}, 'Sentiment'), h('dd', {}, d.sentiment)),
      h('div', {}, h('dt', {}, 'Assigned'), h('dd', {}, d.assignee || 'Nobody')),
      h('div', {}, h('dt', {}, 'Redacted'),
        h('dd', {}, redactions.length ? redactions.map(([k, n]) => `${n} ${k.toLowerCase()}`).join(', ') : 'nothing found'))),
    ready && can('triager') && triageControls(d),
    ready && h('h3', {}, d.kind === 'audio' ? 'Transcript' : 'Content'),
    ready && redactedText(d.redacted_text || ''),
    h('p', { class: 'fineprint mono' }, `sha256 ${d.sha256}`),
  );
}

function triageControls(d) {
  const states = ['new', 'in_progress', 'resolved'];
  const assign = h('select', {
    'aria-label': 'Assign to',
    onchange: (e) => updateItem({ assigned_to: e.target.value ? Number(e.target.value) : null }),
  }, h('option', { value: '' }, 'Unassigned'),
  state.assignees.map((u) => {
    const opt = h('option', { value: String(u.id) }, u.username);
    if (u.id === d.assigned_to) opt.selected = true;
    return opt;
  }));
  return h('div', { class: 'controls' },
    h('div', { class: 'segmented', role: 'group', 'aria-label': 'Triage state' },
      states.map((s) => h('button', {
        class: d.triage_state === s ? 'seg active' : 'seg',
        'aria-pressed': String(d.triage_state === s),
        onclick: () => updateItem({ triage_state: s }),
      }, label(s)))),
    assign,
    d.assigned_to !== state.user.id &&
      h('button', { class: 'ghost', onclick: () => updateItem({ assigned_to: state.user.id }) }, 'Assign to me'),
  );
}

// ---- admin views ---------------------------------------------------------

async function renderAudit() {
  const [list, verify] = await Promise.all([api('/api/audit?limit=200'), api('/api/audit/verify')]);
  const pane = document.querySelector('.admin');
  if (!pane) return;
  pane.replaceChildren(
    h('div', { class: 'admin-head' },
      h('h2', {}, 'Audit log'),
      h('p', { class: `callout ${verify.ok ? 'good' : 'bad'}` },
        verify.ok
          ? `Chain verified: ${verify.checked} entries, none altered.`
          : `Tampering detected at entry ${verify.broken_at}: ${verify.reason}.`),
      h('button', { class: 'ghost', onclick: () => renderAudit().catch((e) => notify(e.message)) }, 'Verify again')),
    h('div', { class: 'table-wrap' },
      h('table', {},
        h('thead', {}, h('tr', {}, ['#', 'Time', 'Actor', 'Action', 'Target', 'Detail'].map((t) => h('th', {}, t)))),
        h('tbody', {}, list.entries.map((e) => h('tr', {},
          h('td', { class: 'mono' }, e.id), h('td', { class: 'nowrap' }, when(e.ts)), h('td', {}, e.actor),
          h('td', { class: 'mono' }, e.action),
          h('td', { class: 'mono', title: e.target || '' }, (e.target || '').replace(/^(item:[0-9a-f]{8})[0-9a-f]+$/, '$1…')),
          h('td', { class: 'mono small' }, Object.keys(e.detail).length ? JSON.stringify(e.detail) : '')))))));
}

async function renderUsers() {
  const { users } = await api('/api/users');
  const pane = document.querySelector('.admin');
  if (!pane) return;
  const form = h('form', {
    class: 'inline-form',
    onsubmit: async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        await api('/api/users', { method: 'POST', json: Object.fromEntries(f) });
        notify(`Created ${f.get('username')}`, 'ok');
        await Promise.all([renderUsers(), loadAssignees()]);
      } catch (err) {
        notify(err.message);
      }
    },
  },
  h('input', { name: 'username', placeholder: 'username', required: true, autocomplete: 'off' }),
  h('input', { name: 'password', type: 'password', placeholder: 'password (12+ characters)', required: true,
    minlength: '12', autocomplete: 'new-password' }),
  h('select', { name: 'role' }, ['viewer', 'triager', 'admin'].map((r) => h('option', { value: r }, r))),
  h('button', { class: 'primary', type: 'submit' }, 'Add user'));

  pane.replaceChildren(
    h('div', { class: 'admin-head' }, h('h2', {}, 'Users')),
    form,
    h('div', { class: 'table-wrap' },
      h('table', {},
        h('thead', {}, h('tr', {}, ['Username', 'Role', 'Status', ''].map((t) => h('th', {}, t)))),
        h('tbody', {}, users.map((u) => h('tr', {},
          h('td', {}, u.username), h('td', {}, u.role), h('td', {}, u.active ? 'Active' : 'Deactivated'),
          h('td', {}, u.id !== state.user.id && h('button', {
            class: 'ghost',
            onclick: async () => {
              try {
                await api(`/api/users/${u.id}`, { method: 'PATCH', json: { active: !u.active } });
                await Promise.all([renderUsers(), loadAssignees()]);
              } catch (err) {
                notify(err.message);
              }
            },
          }, u.active ? 'Deactivate' : 'Reactivate'))))))));
}

// ---- render loop ---------------------------------------------------------

function render() {
  const notice = state.notice &&
    h('div', { class: `notice ${state.notice.kind}`, role: state.notice.kind === 'error' ? 'alert' : 'status' },
      state.notice.message);
  if (!state.user) {
    root.replaceChildren(loginView(), notice || '');
    return;
  }
  // Admin tabs fill their pane asynchronously; keep it if it's already there.
  if (state.tab !== 'queue') {
    const existing = document.querySelector('.admin');
    root.replaceChildren(topBar(), existing || h('main', { class: 'admin' }, h('p', { class: 'muted' }, 'Loading…')),
      notice || '');
    return;
  }
  root.replaceChildren(topBar(), queueView(), notice || '');
}

setInterval(async () => {
  if (!state.user || state.tab !== 'queue' || document.hidden) return;
  try {
    await loadItems();
    render();
  } catch {
    /* the next tick retries */
  }
}, 4000);

(async () => {
  if (await refreshSession()) {
    await Promise.all([loadItems(), loadAssignees()]).catch((err) => notify(err.message));
  }
  render();
})();
