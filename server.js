'use strict';
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { db, dataDir } = require('./db');

const PROD = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const SESSION_HOURS = 12;
const RANK = { superadmin: 4, administrator: 3, teamleader: 2, member: 1 };
const PRIOS = ['low', 'normal', 'high', 'urgent'];
const STATES = ['open', 'in_progress', 'done'];
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 12);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === '1');
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Cache-Control': 'no-store'
  });
  next();
});
app.use(express.json({ limit: '100kb' }));

// ---------- Hilfsfunktionen ----------
const now = () => new Date().toISOString();
const today = () => new Date().toISOString().slice(0, 10);
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const isDate = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && !isNaN(Date.parse(v));

function cookies(h = '') {
  const out = {};
  h.split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return out;
}
function audit(actor, action, target, detail) {
  db.prepare('INSERT INTO audit_log (ts, actor_id, actor_name, action, target, detail) VALUES (?,?,?,?,?,?)')
    .run(now(), actor ? actor.id : null, actor ? actor.username : 'system', action, target || null, detail || null);
}
function notify(userId, text, link) {
  if (!userId) return;
  db.prepare('INSERT INTO notifications (user_id, text, link, created_at) VALUES (?,?,?,?)').run(userId, text, link || null, now());
}
function pwError(pw, username) {
  if (typeof pw !== 'string' || pw.length < 10) return 'Das Passwort muss mindestens 10 Zeichen lang sein.';
  if (pw.length > 200) return 'Das Passwort ist zu lang.';
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return 'Das Passwort braucht mindestens einen Buchstaben und eine Ziffer.';
  if (username && pw.toLowerCase() === username.toLowerCase()) return 'Das Passwort darf nicht dem Benutzernamen entsprechen.';
  return null;
}
const genPassword = () => crypto.randomBytes(9).toString('base64url') + 'a1';
const pub = (u, admin) => ({
  id: u.id, username: u.username, display_name: u.display_name, email: u.email, role: u.role, joined_at: u.joined_at,
  ...(admin ? { locked: !!u.locked, must_change: !!u.must_change } : {})
});

// ---------- Auth ----------
const attempts = new Map();
function throttled(key) {
  const a = attempts.get(key);
  if (!a) return false;
  if (Date.now() - a.first > 15 * 60e3) { attempts.delete(key); return false; }
  return a.n >= 5;
}
function failed(key) {
  const a = attempts.get(key);
  if (!a || Date.now() - a.first > 15 * 60e3) attempts.set(key, { n: 1, first: Date.now() });
  else a.n++;
}

function csrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.get('X-Requested-With') !== 'fetch' || !req.is('application/json')) return bad(res, 'Ungültige Anfrage.', 400);
  next();
}
function auth(req, res, next) {
  const sid = cookies(req.headers.cookie).sid;
  if (!sid) return bad(res, 'Bitte anmelden.', 401);
  const u = db.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
                        WHERE s.token_hash = ? AND s.expires_at > ?`).get(sha(sid), now());
  if (!u || u.locked) return bad(res, 'Sitzung abgelaufen. Bitte neu anmelden.', 401);
  req.user = u; req.sidHash = sha(sid);
  if (u.must_change && !['/me', '/password', '/logout'].includes(req.path)) {
    return res.status(403).json({ error: 'Bitte zuerst das Passwort ändern.', must_change: true });
  }
  next();
}
const need = rank => (req, res, next) => (RANK[req.user.role] >= rank ? next() : bad(res, 'Dafür fehlt dir die Berechtigung.', 403));

const api = express.Router();
api.use(csrf);

api.post('/login', (req, res) => {
  const username = str(req.body.username, 64);
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const key = req.ip + '|' + username.toLowerCase();
  if (throttled(key)) return bad(res, 'Zu viele Versuche. Bitte warte 15 Minuten.', 429);
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = bcrypt.compareSync(password, u ? u.password_hash : DUMMY_HASH);
  if (!u || !ok) { failed(key); return bad(res, 'Benutzername oder Passwort ist falsch.', 401); }
  if (u.locked) return bad(res, 'Dein Konto ist gesperrt. Bitte wende dich an einen Administrator.', 403);
  attempts.delete(key);
  const token = crypto.randomBytes(32).toString('base64url');
  const exp = new Date(Date.now() + SESSION_HOURS * 3600e3);
  db.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)').run(sha(token), u.id, now(), exp.toISOString());
  res.cookie('sid', token, { httpOnly: true, sameSite: 'strict', secure: PROD, path: '/', maxAge: SESSION_HOURS * 3600e3 });
  audit(u, 'login');
  res.json({ ok: true });
});

api.post('/logout', auth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.sidHash);
  res.clearCookie('sid', { path: '/' });
  res.json({ ok: true });
});

api.get('/me', auth, (req, res) => res.json({ user: { ...pub(req.user), must_change: !!req.user.must_change } }));

api.post('/password', auth, (req, res) => {
  const current = typeof req.body.current === 'string' ? req.body.current : '';
  const next = req.body.next;
  if (!bcrypt.compareSync(current, req.user.password_hash)) return bad(res, 'Das aktuelle Passwort ist falsch.', 400);
  const err = pwError(next, req.user.username);
  if (err) return bad(res, err);
  if (next === current) return bad(res, 'Das neue Passwort muss sich vom alten unterscheiden.');
  db.prepare('UPDATE users SET password_hash = ?, must_change = 0 WHERE id = ?').run(bcrypt.hashSync(next, 12), req.user.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').run(req.user.id, req.sidHash);
  audit(req.user, 'password_changed', req.user.username);
  res.json({ ok: true });
});

api.patch('/profile', auth, (req, res) => {
  const name = str(req.body.display_name, 80);
  const email = str(req.body.email, 120);
  if (!name) return bad(res, 'Bitte gib einen Anzeigenamen an.');
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return bad(res, 'Die E-Mail-Adresse ist ungültig.');
  db.prepare('UPDATE users SET display_name = ?, email = ? WHERE id = ?').run(name, email || null, req.user.id);
  audit(req.user, 'profile_updated', req.user.username);
  res.json({ ok: true });
});

// ---------- Benutzer ----------
const canManage = (actor, target) =>
  actor.id !== target.id && target.role !== 'superadmin' &&
  (actor.role === 'superadmin' || (actor.role === 'administrator' && RANK[target.role] <= RANK.teamleader));
const assignable = actor => (actor.role === 'superadmin' ? ['administrator', 'teamleader', 'member'] : ['teamleader', 'member']);

api.get('/users', auth, (req, res) => {
  const admin = RANK[req.user.role] >= 3;
  const rows = db.prepare(`SELECT * FROM users ${admin ? '' : 'WHERE locked = 0'} ORDER BY display_name COLLATE NOCASE`).all();
  res.json({ users: rows.map(u => pub(u, admin)) });
});

api.post('/users', auth, need(3), (req, res) => {
  const username = str(req.body.username, 32);
  const name = str(req.body.display_name, 80);
  const role = req.body.role;
  const joined = isDate(req.body.joined_at) ? req.body.joined_at : today();
  if (!/^[a-z0-9._-]{3,32}$/i.test(username)) return bad(res, 'Der Benutzername braucht 3–32 Zeichen (Buchstaben, Ziffern, . _ -).');
  if (!name) return bad(res, 'Bitte gib einen Anzeigenamen an.');
  if (!assignable(req.user).includes(role)) return bad(res, 'Diese Rolle darfst du nicht vergeben.', 403);
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) return bad(res, 'Dieser Benutzername ist bereits vergeben.', 409);
  let pw = typeof req.body.password === 'string' && req.body.password ? req.body.password : genPassword();
  const err = pwError(pw, username);
  if (err) return bad(res, err);
  const r = db.prepare(`INSERT INTO users (username, display_name, role, password_hash, must_change, joined_at)
                        VALUES (?,?,?,?,1,?)`).run(username, name, role, bcrypt.hashSync(pw, 12), joined);
  audit(req.user, 'user_created', username, 'Rolle: ' + role);
  res.status(201).json({ id: r.lastInsertRowid, temp_password: pw });
});

api.patch('/users/:id', auth, need(3), (req, res) => {
  const t = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.params.id));
  if (!t) return bad(res, 'Benutzer nicht gefunden.', 404);
  if (!canManage(req.user, t)) return bad(res, 'Dieses Konto darfst du nicht verwalten.', 403);
  const out = {};
  if (typeof req.body.locked === 'boolean') {
    db.prepare('UPDATE users SET locked = ? WHERE id = ?').run(req.body.locked ? 1 : 0, t.id);
    if (req.body.locked) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(t.id);
    audit(req.user, req.body.locked ? 'user_locked' : 'user_unlocked', t.username);
  }
  if (req.body.role !== undefined) {
    if (req.user.role !== 'superadmin') return bad(res, 'Nur der Superadmin darf Rollen ändern.', 403);
    if (!assignable(req.user).includes(req.body.role)) return bad(res, 'Ungültige Rolle.');
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(req.body.role, t.id);
    audit(req.user, 'role_changed', t.username, `${t.role} → ${req.body.role}`);
  }
  if (req.body.reset_password === true) {
    const pw = genPassword();
    db.prepare('UPDATE users SET password_hash = ?, must_change = 1 WHERE id = ?').run(bcrypt.hashSync(pw, 12), t.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(t.id);
    audit(req.user, 'password_reset', t.username);
    out.temp_password = pw;
  }
  res.json({ ok: true, ...out });
});

api.delete('/users/:id', auth, need(3), (req, res) => {
  const t = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.params.id));
  if (!t) return bad(res, 'Benutzer nicht gefunden.', 404);
  if (!canManage(req.user, t)) return bad(res, 'Dieses Konto darfst du nicht löschen.', 403);
  db.prepare('DELETE FROM users WHERE id = ?').run(t.id);
  audit(req.user, 'user_deleted', t.username);
  res.json({ ok: true });
});

// ---------- Aufgaben ----------
const TASK_SQL = `SELECT t.*, a.display_name AS assignee_name, c.display_name AS creator_name
                  FROM tasks t LEFT JOIN users a ON a.id = t.assignee_id LEFT JOIN users c ON c.id = t.creator_id`;
const vis = u => (RANK[u.role] >= 3 ? { sql: '1=1', args: [] } : { sql: '(t.assignee_id = ? OR t.creator_id = ?)', args: [u.id, u.id] });
const getTask = (u, id) => { const v = vis(u); return db.prepare(`${TASK_SQL} WHERE t.id = ? AND ${v.sql}`).get(id, ...v.args); };

api.get('/tasks', auth, (req, res) => {
  const v = vis(req.user);
  const tasks = db.prepare(`${TASK_SQL} WHERE ${v.sql} ORDER BY t.status = 'done', t.due IS NULL, t.due, t.id DESC`).all(...v.args);
  res.json({ tasks });
});

api.post('/tasks', auth, (req, res) => {
  const b = req.body;
  const title = str(b.title, 200);
  if (!title) return bad(res, 'Bitte gib einen Titel an.');
  const priority = PRIOS.includes(b.priority) ? b.priority : 'normal';
  if (b.due && !isDate(b.due)) return bad(res, 'Das Fälligkeitsdatum ist ungültig.');
  let assignee = Number(b.assignee_id) || req.user.id;
  if (assignee !== req.user.id && RANK[req.user.role] < 2) return bad(res, 'Du darfst Aufgaben nur dir selbst zuweisen.', 403);
  const au = db.prepare('SELECT id, locked FROM users WHERE id = ?').get(assignee);
  if (!au || au.locked) return bad(res, 'Die zugewiesene Person existiert nicht oder ist gesperrt.');
  const r = db.prepare(`INSERT INTO tasks (title, description, priority, due, assignee_id, creator_id, created_at, updated_at)
                        VALUES (?,?,?,?,?,?,?,?)`).run(title, str(b.description, 5000), priority, b.due || null, assignee, req.user.id, now(), now());
  if (assignee !== req.user.id) notify(assignee, `${req.user.display_name} hat dir die Aufgabe „${title}“ zugewiesen.`, '#/tasks');
  audit(req.user, 'task_created', '#' + r.lastInsertRowid, title);
  res.status(201).json({ id: r.lastInsertRowid });
});

api.get('/tasks/:id', auth, (req, res) => {
  const task = getTask(req.user, Number(req.params.id));
  if (!task) return bad(res, 'Aufgabe nicht gefunden.', 404);
  const comments = db.prepare(`SELECT k.*, u.display_name AS author FROM task_comments k
                               LEFT JOIN users u ON u.id = k.user_id WHERE k.task_id = ? ORDER BY k.id`).all(task.id);
  res.json({ task, comments });
});

api.patch('/tasks/:id', auth, (req, res) => {
  const t = getTask(req.user, Number(req.params.id));
  if (!t) return bad(res, 'Aufgabe nicht gefunden.', 404);
  const full = RANK[req.user.role] >= 3 || t.creator_id === req.user.id;
  const b = req.body;
  const n = { ...t };
  if (full) {
    if (b.title !== undefined) { n.title = str(b.title, 200); if (!n.title) return bad(res, 'Bitte gib einen Titel an.'); }
    if (b.description !== undefined) n.description = str(b.description, 5000);
    if (b.priority !== undefined) { if (!PRIOS.includes(b.priority)) return bad(res, 'Ungültige Priorität.'); n.priority = b.priority; }
    if (b.due !== undefined) { if (b.due && !isDate(b.due)) return bad(res, 'Das Fälligkeitsdatum ist ungültig.'); n.due = b.due || null; }
    if (b.assignee_id !== undefined && Number(b.assignee_id) !== t.assignee_id) {
      if (RANK[req.user.role] < 2) return bad(res, 'Du darfst Aufgaben nicht neu zuweisen.', 403);
      const au = db.prepare('SELECT id, locked FROM users WHERE id = ?').get(Number(b.assignee_id));
      if (!au || au.locked) return bad(res, 'Die zugewiesene Person existiert nicht oder ist gesperrt.');
      n.assignee_id = au.id;
    }
  }
  if (b.status !== undefined) { if (!STATES.includes(b.status)) return bad(res, 'Ungültiger Status.'); n.status = b.status; }
  if (b.progress !== undefined) {
    const p = Number(b.progress);
    if (!Number.isInteger(p) || p < 0 || p > 100) return bad(res, 'Der Fortschritt muss zwischen 0 und 100 liegen.');
    n.progress = p;
  }
  if (n.status === 'done') n.progress = 100;
  else if (n.status === 'open') n.progress = 0;
  else if (n.progress === 100) n.status = 'done';
  db.prepare(`UPDATE tasks SET title=?, description=?, priority=?, due=?, assignee_id=?, status=?, progress=?, updated_at=? WHERE id=?`)
    .run(n.title, n.description, n.priority, n.due, n.assignee_id, n.status, n.progress, now(), t.id);
  if (n.assignee_id !== t.assignee_id && n.assignee_id !== req.user.id)
    notify(n.assignee_id, `${req.user.display_name} hat dir die Aufgabe „${n.title}“ zugewiesen.`, '#/tasks');
  if (n.status !== t.status && t.creator_id && t.creator_id !== req.user.id)
    notify(t.creator_id, `Aufgabe „${n.title}“: Status jetzt „${{ open: 'Offen', in_progress: 'In Bearbeitung', done: 'Erledigt' }[n.status]}“.`, '#/tasks');
  audit(req.user, 'task_updated', '#' + t.id, n.title);
  res.json({ ok: true });
});

api.delete('/tasks/:id', auth, (req, res) => {
  const t = getTask(req.user, Number(req.params.id));
  if (!t) return bad(res, 'Aufgabe nicht gefunden.', 404);
  if (!(RANK[req.user.role] >= 3 || t.creator_id === req.user.id)) return bad(res, 'Nur Ersteller oder Administratoren dürfen Aufgaben löschen.', 403);
  db.prepare('DELETE FROM tasks WHERE id = ?').run(t.id);
  audit(req.user, 'task_deleted', '#' + t.id, t.title);
  res.json({ ok: true });
});

api.post('/tasks/:id/comments', auth, (req, res) => {
  const t = getTask(req.user, Number(req.params.id));
  if (!t) return bad(res, 'Aufgabe nicht gefunden.', 404);
  const body = str(req.body.body, 2000);
  if (!body) return bad(res, 'Der Kommentar darf nicht leer sein.');
  db.prepare('INSERT INTO task_comments (task_id, user_id, body, created_at) VALUES (?,?,?,?)').run(t.id, req.user.id, body, now());
  new Set([t.assignee_id, t.creator_id]).forEach(id => {
    if (id && id !== req.user.id) notify(id, `${req.user.display_name} hat „${t.title}“ kommentiert.`, '#/tasks');
  });
  res.status(201).json({ ok: true });
});

// ---------- Dashboard, Benachrichtigungen, Protokoll ----------
api.get('/dashboard', auth, (req, res) => {
  const u = req.user;
  const mine = db.prepare(`${TASK_SQL} WHERE t.assignee_id = ? AND t.status != 'done' ORDER BY t.due IS NULL, t.due, t.id DESC`).all(u.id);
  const doneCount = db.prepare(`SELECT COUNT(*) c FROM tasks WHERE assignee_id = ? AND status = 'done'`).get(u.id).c;
  const counts = {
    open: mine.filter(t => t.status === 'open').length,
    in_progress: mine.filter(t => t.status === 'in_progress').length,
    overdue: mine.filter(t => t.due && t.due < today()).length,
    done: doneCount
  };
  const notifications = db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 5').all(u.id);
  const unread = db.prepare('SELECT COUNT(*) c FROM notifications WHERE user_id = ? AND read = 0').get(u.id).c;
  const activity = RANK[u.role] >= 3 ? db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 8').all() : null;
  res.json({ tasks: mine.slice(0, 5), counts, notifications, unread, activity });
});

api.get('/notifications', auth, (req, res) => {
  const items = db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 50').all(req.user.id);
  const unread = db.prepare('SELECT COUNT(*) c FROM notifications WHERE user_id = ? AND read = 0').get(req.user.id).c;
  res.json({ items, unread });
});
api.post('/notifications/read', auth, (req, res) => {
  if (req.body.id) db.prepare('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?').run(Number(req.body.id), req.user.id);
  else db.prepare('UPDATE notifications SET read = 1 WHERE user_id = ?').run(req.user.id);
  res.json({ ok: true });
});

api.get('/audit', auth, need(3), (req, res) => {
  res.json({ entries: db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 300').all() });
});

app.use('/api', api);
app.use('/api', (req, res) => bad(res, 'Nicht gefunden.', 404));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return bad(res, 'Ungültige Anfrage.', 400);
  console.error(err);
  bad(res, 'Interner Fehler. Bitte versuche es später erneut.', 500);
});

// ---------- Wartung: Backups & Sitzungen ----------
async function backup() {
  const dir = path.join(dataDir, 'backups');
  fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, `teamhub-${today()}.db`);
  if (fs.existsSync(f)) return;
  await db.backup(f);
  const files = fs.readdirSync(dir).filter(x => x.endsWith('.db')).sort();
  while (files.length > 14) fs.unlinkSync(path.join(dir, files.shift()));
}
const maintain = () => {
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now());
  backup().catch(e => console.error('Backup fehlgeschlagen:', e.message));
};
maintain();
setInterval(maintain, 6 * 3600e3).unref();

app.listen(PORT, HOST, () => console.log(`Team Hub läuft auf http://${HOST}:${PORT}`));
