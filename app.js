'use strict';
const ROLE = { superadmin: 'Superadmin', administrator: 'Administrator', teamleader: 'Teamleitung', member: 'Teammitglied' };
const STATUS = { open: 'Offen', in_progress: 'In Bearbeitung', done: 'Erledigt' };
const PRIO = { low: 'Niedrig', normal: 'Normal', high: 'Hoch', urgent: 'Dringend' };
const RANK = { superadmin: 4, administrator: 3, teamleader: 2, member: 1 };
const ACTIONS = {
  login: 'Angemeldet', password_changed: 'Passwort geändert', profile_updated: 'Profil geändert',
  user_created: 'Benutzer angelegt', user_locked: 'Benutzer gesperrt', user_unlocked: 'Benutzer entsperrt',
  user_deleted: 'Benutzer gelöscht', role_changed: 'Rolle geändert', password_reset: 'Passwort zurückgesetzt',
  task_created: 'Aufgabe erstellt', task_updated: 'Aufgabe geändert', task_deleted: 'Aufgabe gelöscht'
};
let me = null;

const $ = s => document.querySelector(s);
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, '');
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat()) { if (c == null || c === false) continue; e.append(c.nodeType ? c : document.createTextNode(String(c))); }
  return e;
}
async function api(path, method = 'GET', body) {
  const r = await fetch('/api' + path, {
    method, headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' },
    body: body ? JSON.stringify(body) : undefined
  });
  let data = {};
  try { data = await r.json(); } catch { /* leer */ }
  if (!r.ok) { const e = new Error(data.error || 'Unbekannter Fehler.'); e.status = r.status; e.data = data; throw e; }
  return data;
}
function toast(msg, err) {
  const t = h('div', { class: 'toast' + (err ? ' err' : '') }, msg);
  $('#toasts').append(t);
  setTimeout(() => t.remove(), 4000);
}
const fail = e => toast(e.message, true);
const date = s => (s ? new Date(s.length === 10 ? s + 'T00:00:00' : s).toLocaleDateString('de-DE') : '–');
const dtime = s => new Date(s).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
const todayStr = () => new Date().toISOString().slice(0, 10);
const initials = n => n.split(/\s+/).map(x => x[0]).slice(0, 2).join('').toUpperCase();

function setTheme(t) { document.documentElement.dataset.theme = t; localStorage.setItem('theme', t); }
setTheme(localStorage.getItem('theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));

function field(label, input) { return h('label', {}, label, input); }
function opts(map, sel) { return Object.entries(map).map(([k, v]) => h('option', { value: k, selected: k === sel }, v)); }
function modal(title, ...content) {
  const d = h('dialog', {},
    h('div', { class: 'dlg-head' }, h('h2', {}, title), h('button', { class: 'icon', type: 'button', 'aria-label': 'Schließen', onclick: () => d.close() }, '✕')),
    h('div', { class: 'dlg-body' }, ...content));
  d.addEventListener('close', () => d.remove());
  document.body.append(d); d.showModal();
  return d;
}
function secretDialog(title, text, pw) {
  modal(title, h('p', {}, text), h('p', { class: 'secret' }, pw),
    h('p', { class: 'muted' }, 'Das Passwort wird nur einmal angezeigt. Die Person muss es beim ersten Login ändern.'));
}

// ---------- Anmeldung ----------
function loginView() {
  const err = h('p', { class: 'error', role: 'alert' });
  const form = h('form', { onsubmit: async ev => {
    ev.preventDefault(); err.textContent = '';
    try {
      await api('/login', 'POST', { username: form.u.value, password: form.p.value });
      me = (await api('/me')).user; start();
    } catch (e) { err.textContent = e.message; }
  } },
    field('Benutzername', h('input', { name: 'u', autocomplete: 'username', required: true, autofocus: true })),
    field('Passwort', h('input', { name: 'p', type: 'password', autocomplete: 'current-password', required: true })),
    err, h('button', { class: 'primary' }, 'Anmelden'));
  $('#root').replaceChildren(h('div', { class: 'auth' }, h('div', { class: 'card' }, h('h1', {}, 'Team Hub'), form)));
}
function forcedPasswordView() {
  const err = h('p', { class: 'error', role: 'alert' });
  const form = h('form', { onsubmit: async ev => {
    ev.preventDefault(); err.textContent = '';
    if (form.n.value !== form.r.value) { err.textContent = 'Die neuen Passwörter stimmen nicht überein.'; return; }
    try { await api('/password', 'POST', { current: form.c.value, next: form.n.value }); me.must_change = false; toast('Passwort geändert.'); start(); }
    catch (e) { err.textContent = e.message; }
  } },
    h('p', {}, 'Bitte lege jetzt ein eigenes Passwort fest (mindestens 10 Zeichen, mit Buchstaben und Ziffern).'),
    field('Temporäres Passwort', h('input', { name: 'c', type: 'password', autocomplete: 'current-password', required: true })),
    field('Neues Passwort', h('input', { name: 'n', type: 'password', autocomplete: 'new-password', required: true })),
    field('Neues Passwort wiederholen', h('input', { name: 'r', type: 'password', autocomplete: 'new-password', required: true })),
    err, h('div', { class: 'actions' }, h('button', { type: 'button', onclick: logout }, 'Abmelden'), h('button', { class: 'primary' }, 'Passwort speichern')));
  $('#root').replaceChildren(h('div', { class: 'auth' }, h('div', { class: 'card' }, h('h1', {}, 'Passwort ändern'), form)));
}
async function logout() { try { await api('/logout', 'POST'); } catch { /* egal */ } me = null; loginView(); }

// ---------- Shell & Routing ----------
const NAV = [
  ['dashboard', 'Übersicht'], ['tasks', 'Aufgaben'], ['team', 'Team'], ['notifications', 'Benachrichtigungen'],
  ['users', 'Benutzer', 3], ['audit', 'Aktivitätsprotokoll', 3], ['account', 'Mein Konto']
];
function shell() {
  const side = h('aside', { id: 'side' }, h('div', { class: 'brand' }, 'Team Hub'),
    h('nav', {}, NAV.filter(n => !n[2] || RANK[me.role] >= n[2]).map(([r, l]) =>
      h('a', { href: '#/' + r, 'data-r': r }, l, r === 'notifications' ? h('span', { class: 'badge', id: 'nb', hidden: true }) : null))));
  const toggle = () => side.classList.toggle('open');
  $('#root').replaceChildren(h('div', { class: 'app' }, side, h('div', { class: 'backdrop', onclick: toggle }),
    h('div', { class: 'main' },
      h('header', { class: 'top' },
        h('button', { class: 'icon menu', 'aria-label': 'Menü', onclick: toggle }, '☰'), h('span', { class: 'grow' }),
        h('button', { class: 'icon', 'aria-label': 'Hell/Dunkel umschalten', onclick: () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark') }, '◐'),
        h('span', { class: 'muted' }, me.display_name), h('button', { onclick: logout }, 'Abmelden')),
      h('main', { id: 'view', tabindex: '-1' }))));
}
function setBadge(n) { const b = $('#nb'); if (!b) return; b.hidden = !n; b.textContent = n; }
async function refreshBadge() { try { setBadge((await api('/notifications')).unread); } catch { /* egal */ } }

const routes = { dashboard: viewDashboard, tasks: viewTasks, team: viewTeam, notifications: viewNotifications, users: viewUsers, audit: viewAudit, account: viewAccount };
async function route() {
  if (!me || me.must_change) return;
  const name = location.hash.slice(2) || 'dashboard';
  const fn = routes[name];
  if (!fn || (['users', 'audit'].includes(name) && RANK[me.role] < 3)) { location.hash = '#/dashboard'; return; }
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('active', a.dataset.r === name));
  $('#side').classList.remove('open');
  const v = $('#view'); v.replaceChildren();
  try { await fn(v); } catch (e) {
    if (e.status === 401) { me = null; loginView(); return; }
    v.append(h('p', { class: 'error' }, e.message));
  }
  refreshBadge();
}
function start() {
  if (me.must_change) return forcedPasswordView();
  shell(); route();
}
window.addEventListener('hashchange', route);
(async () => {
  try { me = (await api('/me')).user; start(); } catch { loginView(); }
  setInterval(() => { if (me && !me.must_change) refreshBadge(); }, 60000);
})();

// ---------- Übersicht ----------
const stat = (label, n, cls) => h('div', { class: 'stat ' + (cls || '') }, h('b', {}, n), h('span', {}, label));
async function viewDashboard(v) {
  const d = await api('/dashboard');
  const hr = new Date().getHours();
  const greet = hr < 11 ? 'Guten Morgen' : hr < 18 ? 'Guten Tag' : 'Guten Abend';
  v.append(h('h1', {}, `${greet}, ${me.display_name.split(' ')[0]}`),
    h('div', { class: 'stats' }, stat('Offen', d.counts.open), stat('In Bearbeitung', d.counts.in_progress),
      stat('Überfällig', d.counts.overdue, d.counts.overdue ? 'warn' : ''), stat('Erledigt', d.counts.done)),
    h('div', { class: 'grid' },
      h('section', { class: 'card' }, h('h2', {}, 'Meine nächsten Aufgaben'),
        d.tasks.length ? h('ul', { class: 'list' }, d.tasks.map(t => h('li', {},
          h('button', { class: 'linkbtn', onclick: () => taskDialog(t.id, route) }, t.title),
          h('div', { class: 'muted' }, STATUS[t.status], ' · fällig ', h('span', { class: t.due && t.due < todayStr() ? 'overdue' : '' }, date(t.due)))))) :
          h('p', { class: 'muted' }, 'Keine offenen Aufgaben. Unter „Aufgaben“ kannst du eine neue anlegen.')),
      h('section', { class: 'card' }, h('h2', {}, 'Neueste Benachrichtigungen'),
        d.notifications.length ? h('ul', { class: 'list' }, d.notifications.map(n => h('li', { class: n.read ? '' : 'unread' }, n.text, h('div', { class: 'muted' }, dtime(n.created_at))))) :
          h('p', { class: 'muted' }, 'Noch keine Benachrichtigungen.')),
      d.activity && h('section', { class: 'card' }, h('h2', {}, 'Letzte Teamaktivitäten'),
        d.activity.length ? h('ul', { class: 'list' }, d.activity.map(a => h('li', {}, `${a.actor_name}: ${ACTIONS[a.action] || a.action}`, a.target ? ` (${a.target})` : '', h('div', { class: 'muted' }, dtime(a.ts))))) :
          h('p', { class: 'muted' }, 'Noch keine Aktivitäten.'))));
}

// ---------- Aufgaben ----------
async function viewTasks(v) {
  const { tasks } = await api('/tasks');
  const body = h('tbody'), filt = h('select', {}, h('option', { value: 'all' }, 'Alle sichtbaren'), h('option', { value: 'mine' }, 'Mir zugewiesen'), h('option', { value: 'created' }, 'Von mir erstellt')),
    st = h('select', {}, h('option', { value: '' }, 'Jeder Status'), opts(STATUS));
  const draw = () => {
    const rows = tasks.filter(t => (filt.value === 'all' || (filt.value === 'mine' && t.assignee_id === me.id) || (filt.value === 'created' && t.creator_id === me.id)) && (!st.value || t.status === st.value));
    body.replaceChildren(...(rows.length ? rows.map(t => h('tr', {},
      h('td', {}, h('button', { class: 'linkbtn', onclick: () => taskDialog(t.id, route) }, t.title)),
      h('td', {}, t.assignee_name || '–'),
      h('td', {}, h('span', { class: 'pill ' + t.priority }, PRIO[t.priority])),
      h('td', { class: t.due && t.due < todayStr() && t.status !== 'done' ? 'overdue' : '' }, date(t.due)),
      h('td', {}, STATUS[t.status]),
      h('td', {}, h('progress', { max: 100, value: t.progress }), ' ', t.progress + ' %'))) :
      [h('tr', {}, h('td', { colspan: 6, class: 'muted' }, 'Keine Aufgaben für diese Auswahl.'))]));
  };
  filt.onchange = st.onchange = draw; draw();
  v.append(h('h1', {}, 'Aufgaben'),
    h('div', { class: 'toolbar' }, filt, st, h('span', { class: 'grow' }), h('button', { class: 'primary', onclick: () => taskDialog(null, route) }, 'Neue Aufgabe')),
    h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Titel', 'Zuständig', 'Priorität', 'Fällig', 'Status', 'Fortschritt'].map(x => h('th', {}, x)))), body)));
}

async function taskDialog(id, onSaved) {
  const users = (await api('/users')).users.filter(u => !u.locked);
  const detail = id ? await api('/tasks/' + id) : null;
  const t = detail ? detail.task : null;
  const full = !t || RANK[me.role] >= 3 || t.creator_id === me.id;
  const canAssign = RANK[me.role] >= 2 && full;
  const err = h('p', { class: 'error', role: 'alert' });
  const f = {
    title: h('input', { value: t ? t.title : '', required: true, maxlength: 200, disabled: !full }),
    desc: h('textarea', { disabled: !full, maxlength: 5000 }, t ? t.description : ''),
    prio: h('select', { disabled: !full }, opts(PRIO, t ? t.priority : 'normal')),
    due: h('input', { type: 'date', value: t && t.due ? t.due : '', disabled: !full }),
    who: h('select', { disabled: !canAssign }, users.map(u => h('option', { value: u.id, selected: u.id === (t ? t.assignee_id : me.id) }, u.display_name))),
    status: h('select', {}, opts(STATUS, t ? t.status : 'open')),
    prog: h('input', { type: 'range', min: 0, max: 100, step: 5, value: t ? t.progress : 0 })
  };
  const form = h('form', { onsubmit: async ev => {
    ev.preventDefault(); err.textContent = '';
    const b = full ? { title: f.title.value, description: f.desc.value, priority: f.prio.value, due: f.due.value || null } : {};
    if (canAssign || !t) b.assignee_id = Number(f.who.value);
    if (t) { b.status = f.status.value; b.progress = Number(f.prog.value); }
    try { await api(t ? '/tasks/' + t.id : '/tasks', t ? 'PATCH' : 'POST', b); d.close(); toast('Gespeichert.'); onSaved(); } catch (e) { err.textContent = e.message; }
  } },
    field('Titel', f.title), field('Beschreibung', f.desc),
    h('div', { class: 'two' }, field('Priorität', f.prio), field('Fällig am', f.due)),
    field('Zuständig', f.who),
    t && h('div', { class: 'two' }, field('Status', f.status), field('Fortschritt', f.prog)),
    err,
    h('div', { class: 'actions' },
      t && full && h('button', { type: 'button', class: 'danger', onclick: async () => {
        if (!confirm('Aufgabe wirklich löschen?')) return;
        try { await api('/tasks/' + t.id, 'DELETE'); d.close(); toast('Gelöscht.'); onSaved(); } catch (e) { fail(e); }
      } }, 'Löschen'),
      h('span', { class: 'grow' }), h('button', { class: 'primary' }, 'Speichern')));
  let comments = null;
  if (t) {
    const list = h('ul', { class: 'list' }, detail.comments.map(k => h('li', {}, h('b', {}, k.author || 'Gelöschter Benutzer'), ' ', h('span', { class: 'muted' }, dtime(k.created_at)), h('div', {}, k.body))));
    const inp = h('input', { placeholder: 'Kommentar schreiben …', maxlength: 2000 });
    comments = h('div', {}, h('h2', {}, 'Kommentare'), detail.comments.length ? list : h('p', { class: 'muted' }, 'Noch keine Kommentare.'),
      h('form', { class: 'toolbar', onsubmit: async ev => {
        ev.preventDefault(); if (!inp.value.trim()) return;
        try { await api(`/tasks/${t.id}/comments`, 'POST', { body: inp.value }); d.close(); taskDialog(t.id, onSaved); } catch (e) { fail(e); }
      } }, h('span', { class: 'grow' }, inp), h('button', {}, 'Senden')));
  }
  const d = modal(t ? 'Aufgabe bearbeiten' : 'Neue Aufgabe', form, comments);
}

// ---------- Team ----------
async function viewTeam(v) {
  const { users } = await api('/users');
  v.append(h('h1', {}, 'Team'), h('div', { class: 'people' }, users.map(u => h('div', { class: 'card' },
    h('div', { class: 'avatar', 'aria-hidden': 'true' }, initials(u.display_name)),
    h('b', {}, u.display_name), h('div', { class: 'muted' }, ROLE[u.role]),
    h('div', { class: 'muted' }, 'Im Team seit ', date(u.joined_at)),
    u.email ? h('a', { href: 'mailto:' + u.email }, u.email) : h('span', { class: 'muted' }, 'Keine E-Mail hinterlegt'),
    u.locked && h('div', {}, h('span', { class: 'pill urgent' }, 'Gesperrt'))))));
}

// ---------- Benachrichtigungen ----------
async function viewNotifications(v) {
  const { items } = await api('/notifications');
  v.append(h('h1', {}, 'Benachrichtigungen'),
    h('div', { class: 'toolbar' }, h('button', { disabled: !items.some(i => !i.read), onclick: async () => { await api('/notifications/read', 'POST', {}); route(); } }, 'Alle als gelesen markieren')),
    h('div', { class: 'card' }, items.length ? h('ul', { class: 'list' }, items.map(n => h('li', { class: n.read ? '' : 'unread' },
      n.link ? h('a', { href: n.link, onclick: () => api('/notifications/read', 'POST', { id: n.id }) }, n.text) : n.text,
      h('div', { class: 'muted' }, dtime(n.created_at))))) : h('p', { class: 'muted' }, 'Keine Benachrichtigungen.')));
}

// ---------- Benutzerverwaltung ----------
async function viewUsers(v) {
  const { users } = await api('/users');
  const isSuper = me.role === 'superadmin';
  const manage = u => u.id !== me.id && u.role !== 'superadmin' && (isSuper || RANK[u.role] <= 2);
  const act = async (fn, okMsg) => { try { const r = await fn(); if (okMsg) toast(okMsg); route(); return r; } catch (e) { fail(e); } };
  v.append(h('h1', {}, 'Benutzer'),
    h('div', { class: 'toolbar' }, h('span', { class: 'grow' }), h('button', { class: 'primary', onclick: () => createUserDialog(isSuper) }, 'Benutzer anlegen')),
    h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Name', 'Benutzername', 'Rolle', 'Status', 'Aktionen'].map(x => h('th', {}, x)))),
      h('tbody', {}, users.map(u => h('tr', {},
        h('td', {}, u.display_name), h('td', {}, u.username),
        h('td', {}, isSuper && manage(u) ? h('select', { 'aria-label': 'Rolle', onchange: ev => act(() => api('/users/' + u.id, 'PATCH', { role: ev.target.value }), 'Rolle geändert.') },
          ['administrator', 'teamleader', 'member'].map(r => h('option', { value: r, selected: r === u.role }, ROLE[r]))) : ROLE[u.role]),
        h('td', {}, u.locked ? h('span', { class: 'pill urgent' }, 'Gesperrt') : u.must_change ? h('span', { class: 'pill' }, 'Passwort offen') : 'Aktiv'),
        h('td', {}, manage(u) ? h('div', { class: 'row-actions' },
          h('button', { onclick: () => act(() => api('/users/' + u.id, 'PATCH', { locked: !u.locked }), u.locked ? 'Entsperrt.' : 'Gesperrt.') }, u.locked ? 'Entsperren' : 'Sperren'),
          h('button', { onclick: async () => { if (!confirm(`Passwort von ${u.display_name} zurücksetzen?`)) return; const r = await act(() => api('/users/' + u.id, 'PATCH', { reset_password: true })); if (r) secretDialog('Neues temporäres Passwort', `Für ${u.username}:`, r.temp_password); } }, 'Passwort zurücksetzen'),
          h('button', { class: 'danger', onclick: () => { if (confirm(`${u.display_name} endgültig löschen?`)) act(() => api('/users/' + u.id, 'DELETE'), 'Gelöscht.'); } }, 'Löschen')) : h('span', { class: 'muted' }, '–'))))))));
}
function createUserDialog(isSuper) {
  const err = h('p', { class: 'error', role: 'alert' });
  const form = h('form', { onsubmit: async ev => {
    ev.preventDefault(); err.textContent = '';
    try {
      const r = await api('/users', 'POST', { username: form.u.value, display_name: form.n.value, role: form.r.value, password: form.p.value || undefined, joined_at: form.j.value || undefined });
      d.close(); secretDialog('Benutzer angelegt', `Zugangsdaten für ${form.u.value}:`, r.temp_password); route();
    } catch (e) { err.textContent = e.message; }
  } },
    h('div', { class: 'two' }, field('Benutzername', h('input', { name: 'u', required: true, autocomplete: 'off' })), field('Anzeigename', h('input', { name: 'n', required: true }))),
    h('div', { class: 'two' }, field('Rolle', h('select', { name: 'r' }, (isSuper ? ['administrator', 'teamleader', 'member'] : ['teamleader', 'member']).map(r => h('option', { value: r, selected: r === 'member' }, ROLE[r])))),
      field('Eintrittsdatum', h('input', { name: 'j', type: 'date' }))),
    field('Temporäres Passwort (leer lassen = automatisch erzeugen)', h('input', { name: 'p', autocomplete: 'off' })),
    err, h('div', { class: 'actions' }, h('button', { class: 'primary' }, 'Anlegen')));
  const d = modal('Benutzer anlegen', form);
}

// ---------- Protokoll ----------
async function viewAudit(v) {
  const { entries } = await api('/audit');
  v.append(h('h1', {}, 'Aktivitätsprotokoll'), h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Zeitpunkt', 'Von', 'Aktion', 'Betrifft', 'Details'].map(x => h('th', {}, x)))),
    h('tbody', {}, entries.length ? entries.map(a => h('tr', {}, h('td', {}, dtime(a.ts)), h('td', {}, a.actor_name), h('td', {}, ACTIONS[a.action] || a.action), h('td', {}, a.target || '–'), h('td', {}, a.detail || '–'))) :
      [h('tr', {}, h('td', { colspan: 5, class: 'muted' }, 'Noch keine Einträge.'))]))));
}

// ---------- Mein Konto ----------
async function viewAccount(v) {
  const perr = h('p', { class: 'error', role: 'alert' }), merr = h('p', { class: 'error', role: 'alert' });
  const prof = h('form', { onsubmit: async ev => {
    ev.preventDefault(); merr.textContent = '';
    try { await api('/profile', 'PATCH', { display_name: prof.n.value, email: prof.e.value }); me = (await api('/me')).user; toast('Profil gespeichert.'); shell(); route(); } catch (e) { merr.textContent = e.message; }
  } },
    field('Anzeigename', h('input', { name: 'n', value: me.display_name, required: true })),
    field('E-Mail (freiwillig)', h('input', { name: 'e', type: 'email', value: me.email || '' })), merr,
    h('div', { class: 'actions' }, h('button', { class: 'primary' }, 'Profil speichern')));
  const pw = h('form', { onsubmit: async ev => {
    ev.preventDefault(); perr.textContent = '';
    if (pw.n.value !== pw.r.value) { perr.textContent = 'Die neuen Passwörter stimmen nicht überein.'; return; }
    try { await api('/password', 'POST', { current: pw.c.value, next: pw.n.value }); pw.reset(); toast('Passwort geändert. Andere Geräte wurden abgemeldet.'); } catch (e) { perr.textContent = e.message; }
  } },
    field('Aktuelles Passwort', h('input', { name: 'c', type: 'password', autocomplete: 'current-password', required: true })),
    field('Neues Passwort', h('input', { name: 'n', type: 'password', autocomplete: 'new-password', required: true })),
    field('Neues Passwort wiederholen', h('input', { name: 'r', type: 'password', autocomplete: 'new-password', required: true })), perr,
    h('div', { class: 'actions' }, h('button', { class: 'primary' }, 'Passwort ändern')));
  v.append(h('h1', {}, 'Mein Konto'), h('p', { class: 'muted' }, `${me.username} · ${ROLE[me.role]} · im Team seit ${date(me.joined_at)}`),
    h('div', { class: 'grid' }, h('section', { class: 'card' }, h('h2', {}, 'Profil'), prof), h('section', { class: 'card' }, h('h2', {}, 'Passwort ändern'), pw)));
}
