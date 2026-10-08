'use strict';
const express = require('express');
const multer = require('multer');
let Database;
try { Database = require('better-sqlite3'); } catch { Database = require('./sqlite-shim'); }
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const QRCode = require('qrcode');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'cambiar123';
const BRAND = process.env.BRAND_NAME || 'MiFirma';
const MAX_MB = 20;

for (const d of ['docs', 'final']) fs.mkdirSync(path.join(DATA_DIR, d), { recursive: true });

// ---------- secreto de sesión ----------
const secretFile = path.join(DATA_DIR, 'secret.txt');
if (!fs.existsSync(secretFile)) fs.writeFileSync(secretFile, crypto.randomBytes(32).toString('hex'));
const SECRET = process.env.SESSION_SECRET || fs.readFileSync(secretFile, 'utf8').trim();

// ---------- base de datos ----------
const db = new Database(path.join(DATA_DIR, 'firma.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, sha256 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pendiente', created_at TEXT NOT NULL,
  completed_at TEXT, final_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS signers (
  id INTEGER PRIMARY KEY AUTOINCREMENT, doc_id TEXT NOT NULL, name TEXT NOT NULL,
  contact TEXT, token TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'pendiente',
  signed_at TEXT, signed_name TEXT, ip TEXT, ua TEXT, signature_png BLOB, opened_at TEXT
);
`);
// Migración segura: agrega las columnas de revocación si la base es anterior
{
  const cols = db.prepare('PRAGMA table_info(documents)').all().map((c) => c.name);
  for (const c of ['revoked_at', 'revoked_reason', 'revoked_ip']) {
    if (!cols.includes(c)) db.exec(`ALTER TABLE documents ADD COLUMN ${c} TEXT`);
  }
}

// ---------- utilidades ----------
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const newId = () => crypto.randomBytes(9).toString('base64url');
const newToken = () => crypto.randomBytes(24).toString('base64url');
const fmtDate = (iso) => iso ? new Date(iso).toLocaleString('es-AR', { timeZone: 'America/Argentina/Buenos_Aires' }) : '';

const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'no-referrer');
  next();
});
app.use('/pdfjs', express.static(path.join(__dirname, 'node_modules', 'pdfjs-dist', 'legacy', 'build'), { maxAge: '7d' }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_MB * 1024 * 1024 } });

const baseUrl = (req) => process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
const clientIp = (req) => req.ip || req.socket.remoteAddress || '';

// ---------- sesión de administrador (cookie firmada) ----------
const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
function getCookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}
function isAdmin(req) {
  const c = getCookie(req, 'adm');
  if (!c) return false;
  const [exp, mac] = c.split('.');
  if (!exp || !mac || Number(exp) < Date.now()) return false;
  const good = sign('adm' + exp);
  return mac.length === good.length && crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(good));
}
function requireAdmin(req, res, next) {
  if (isAdmin(req)) return next();
  res.redirect('/login');
}
const attempts = new Map();
function tooMany(ip) {
  const now = Date.now();
  const list = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60 * 1000);
  attempts.set(ip, list);
  return list.length >= 8;
}

// ---------- plantilla HTML ----------
const CSS = `
:root{--ink:#1F2170;--ink2:#2d30a0;--bg:#f5f6fb;--card:#fff;--tx:#1b1d2b;--mut:#666b85;--ok:#14804a;--warn:#b26a00;--line:#e3e5f0}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--tx);line-height:1.45}
header{background:var(--ink);color:#fff;padding:14px 16px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
header a{color:#fff;text-decoration:none}header .logo{font-weight:700;font-size:20px}
header nav a{margin-left:14px;font-size:15px;opacity:.9}
main{max-width:860px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px}
h1{font-size:22px;margin:6px 0 14px}h2{font-size:17px;margin:0 0 10px}
label{display:block;font-weight:600;margin:12px 0 4px;font-size:14px}
input[type=text],input[type=password],input[type=file],input[type=date],select,textarea{width:100%;padding:12px;border:1px solid #c9cde0;border-radius:8px;font-size:16px;background:#fff}
.btn{display:inline-block;background:var(--ink);color:#fff;border:0;border-radius:10px;padding:13px 18px;font-size:16px;font-weight:600;cursor:pointer;text-decoration:none;text-align:center}
.btn:hover{background:var(--ink2)}.btn.sec{background:#fff;color:var(--ink);border:1px solid var(--ink)}
.btn.wa{background:#1fa855}.btn.red{background:#b3261e}.btn.small{padding:8px 12px;font-size:14px}
.btn[disabled]{opacity:.45;cursor:not-allowed}
.badge{display:inline-block;border-radius:999px;padding:2px 10px;font-size:13px;font-weight:600}
.b-ok{background:#dff5e8;color:var(--ok)}.b-pend{background:#fff0d6;color:var(--warn)}.b-rev{background:#fde8e6;color:#8f1d16}
summary{cursor:pointer}
table{width:100%;border-collapse:collapse}td,th{padding:10px 6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:15px}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>*{flex:1 1 200px}
.mut{color:var(--mut);font-size:14px}.err{background:#fde8e6;color:#8f1d16;padding:10px 12px;border-radius:8px;margin-bottom:12px}
.ok{background:#dff5e8;color:#0e5c35;padding:10px 12px;border-radius:8px;margin-bottom:12px}
code,.mono{font-family:ui-monospace,Menlo,monospace;font-size:13px;word-break:break-all}
.link{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
`;
function page(title, body, req, opts = {}) {
  const nav = opts.admin ? `<nav><a href="/">Documentos</a><a href="/nuevo">Nuevo</a><a href="/recibos">Recibos</a><a href="/verificar">Verificar</a><a href="/ajustes">Ajustes</a><form method="post" action="/logout" style="display:inline"><button class="btn small sec" style="margin-left:14px">Salir</button></form></nav>` : '';
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)} · ${esc(BRAND)}</title><style>${CSS}${opts.css || ''}</style></head><body><header><a class="logo" href="/">${esc(BRAND)}</a>${nav}</header><main>${body}</main>${opts.script || ''}</body></html>`;
}

// ---------- login ----------
app.get('/login', (req, res) => {
  const warn = ADMIN_PASSWORD === 'cambiar123' ? '<div class="err">Estás usando la contraseña de ejemplo (<b>cambiar123</b>). Cambiala con la variable ADMIN_PASSWORD antes de publicar esto en internet.</div>' : '';
  res.send(page('Ingresar', `<div class="card" style="max-width:420px;margin:30px auto"><h1>Ingresar</h1>${warn}${req.query.e ? '<div class="err">Contraseña incorrecta.</div>' : ''}<form method="post" action="/login"><label>Contraseña</label><input type="password" name="password" autofocus><p><button class="btn" style="width:100%">Entrar</button></p></form></div>`, req));
});
app.post('/login', (req, res) => {
  const ip = clientIp(req);
  if (tooMany(ip)) return res.status(429).send('Demasiados intentos. Probá en 15 minutos.');
  const a = Buffer.from(sha256(String(req.body.password || '')));
  const b = Buffer.from(sha256(ADMIN_PASSWORD));
  if (!crypto.timingSafeEqual(a, b)) {
    attempts.get(ip).push(Date.now());
    return res.redirect('/login?e=1');
  }
  const exp = Date.now() + 7 * 24 * 3600 * 1000;
  const secure = req.protocol === 'https' ? '; Secure' : '';
  res.set('Set-Cookie', `adm=${exp}.${sign('adm' + exp)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 3600}${secure}`);
  res.redirect('/');
});
app.post('/logout', (req, res) => {
  res.set('Set-Cookie', 'adm=; HttpOnly; Path=/; Max-Age=0');
  res.redirect('/login');
});

// ---------- panel: lista ----------
app.get('/', requireAdmin, (req, res) => {
  const docs = db.prepare('SELECT * FROM documents ORDER BY created_at DESC').all();
  const cnt = db.prepare("SELECT doc_id, COUNT(*) t, SUM(status='firmado') f FROM signers GROUP BY doc_id").all();
  const m = Object.fromEntries(cnt.map((c) => [c.doc_id, c]));
  const rows = docs.map((d) => {
    const c = m[d.id] || { t: 0, f: 0 };
    const badge = d.revoked_at ? '<span class="badge b-rev">Revocado</span>' : (d.status === 'firmado' ? '<span class="badge b-ok">Firmado</span>' : '<span class="badge b-pend">Pendiente</span>');
    return `<tr><td><a href="/doc/${d.id}"><b>${esc(d.title)}</b></a><div class="mut">${fmtDate(d.created_at)}</div></td><td>${c.f || 0}/${c.t}</td><td>${badge}</td></tr>`;
  }).join('');
  res.send(page('Documentos', `<h1>Documentos</h1><p><a class="btn" href="/nuevo">+ Enviar un documento a firmar</a></p><div class="card">${docs.length ? `<table><tr><th>Documento</th><th>Firmas</th><th>Estado</th></tr>${rows}</table>` : '<p class="mut">Todavía no enviaste ningún documento.</p>'}</div>`, req, { admin: true }));
});

// ---------- panel: nuevo ----------
app.get('/nuevo', requireAdmin, (req, res) => {
  const signerBox = (i) => `<div class="card" style="background:#fafbff"><b>Firmante ${i}</b><div class="row"><div><label>Nombre y apellido</label><input type="text" name="name" ${i === 1 ? 'required' : ''}></div><div><label>WhatsApp o email (opcional)</label><input type="text" name="contact" placeholder="+54 9 11 ..."></div></div></div>`;
  res.send(page('Nuevo documento', `<h1>Enviar un documento a firmar</h1>${req.query.e ? `<div class="err">${esc(req.query.e)}</div>` : ''}
<form method="post" action="/nuevo" enctype="multipart/form-data" class="card">
<label>Archivo PDF (hasta ${MAX_MB} MB)</label><input type="file" name="pdf" accept="application/pdf" required>
<label>Título del documento</label><input type="text" name="title" placeholder="Ej: Contrato de servicios" required>
<h2 style="margin-top:20px">¿Quién tiene que firmar?</h2>
${signerBox(1)}${signerBox(2)}${signerBox(3)}
<p class="mut">Dejá vacíos los firmantes que no necesites.</p>
<button class="btn">Crear y obtener los links</button></form>`, req, { admin: true }));
});

app.post('/nuevo', requireAdmin, upload.single('pdf'), async (req, res) => {
  try {
    const title = String(req.body.title || '').trim().slice(0, 200);
    if (!req.file || !title) return res.redirect('/nuevo?e=' + encodeURIComponent('Falta el archivo o el título.'));
    const names = [].concat(req.body.name || []);
    const contacts = [].concat(req.body.contact || []);
    const signers = names.map((n, i) => ({ name: String(n).trim().slice(0, 120), contact: String(contacts[i] || '').trim().slice(0, 120) })).filter((s) => s.name);
    if (!signers.length) return res.redirect('/nuevo?e=' + encodeURIComponent('Agregá al menos un firmante.'));
    const buf = req.file.buffer;
    if (buf.slice(0, 5).toString() !== '%PDF-') return res.redirect('/nuevo?e=' + encodeURIComponent('El archivo no es un PDF.'));
    try { await PDFDocument.load(buf, { ignoreEncryption: true }); }
    catch { return res.redirect('/nuevo?e=' + encodeURIComponent('No se pudo leer ese PDF. Probá guardarlo de nuevo como PDF.')); }
    const id = newId();
    fs.writeFileSync(path.join(DATA_DIR, 'docs', id + '.pdf'), buf);
    db.prepare('INSERT INTO documents (id,title,sha256,created_at) VALUES (?,?,?,?)').run(id, title, sha256(buf), new Date().toISOString());
    const ins = db.prepare('INSERT INTO signers (doc_id,name,contact,token) VALUES (?,?,?,?)');
    for (const s of signers) ins.run(id, s.name, s.contact, newToken());
    res.redirect('/doc/' + id);
  } catch (e) {
    console.error(e);
    res.redirect('/nuevo?e=' + encodeURIComponent('Error al crear el documento.'));
  }
});

// ---------- panel: detalle ----------
function waLink(contact, text) {
  const digits = String(contact || '').replace(/\D/g, '');
  if (!digits || String(contact).includes('@')) return null;
  return `https://wa.me/${digits}?text=${encodeURIComponent(text)}`;
}
app.get('/doc/:id', requireAdmin, (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).send('No existe');
  const sg = db.prepare('SELECT id,name,contact,token,status,signed_at,opened_at FROM signers WHERE doc_id=? ORDER BY id').all(d.id);
  const rows = sg.map((s) => {
    const url = `${baseUrl(req)}/firmar/${s.token}`;
    const msg = `Hola ${s.name}, te envío "${d.title}" para firmar. Abrilo desde el celular y firmá con el dedo: ${url}`;
    const wa = waLink(s.contact, msg);
    const mail = String(s.contact).includes('@') ? `mailto:${s.contact}?subject=${encodeURIComponent('Documento para firmar: ' + d.title)}&body=${encodeURIComponent(msg)}` : null;
    const st = s.status === 'firmado' ? `<span class="badge b-ok">Firmó ${fmtDate(s.signed_at)}</span>` : (s.opened_at ? '<span class="badge b-pend">Lo abrió, falta firmar</span>' : '<span class="badge b-pend">Sin abrir</span>');
    return `<div class="card"><b>${esc(s.name)}</b> ${esc(s.contact)}<div style="margin:6px 0">${st}</div>${(s.status === 'firmado' || d.revoked_at) ? '' : `<div class="link"><input type="text" readonly value="${esc(url)}" onclick="this.select()" style="flex:1 1 240px">${wa ? `<a class="btn wa small" target="_blank" rel="noopener" href="${esc(wa)}">Enviar por WhatsApp</a>` : ''}${mail ? `<a class="btn small sec" href="${esc(mail)}">Enviar por email</a>` : ''}<button type="button" class="btn small sec" onclick="navigator.clipboard.writeText('${esc(url)}');this.textContent='¡Copiado!'">Copiar link</button></div>`}</div>`;
  }).join('');
  const done = d.status === 'firmado';
  const revBanner = d.revoked_at ? `<div class="err"><b>Documento REVOCADO</b> el ${fmtDate(d.revoked_at)}.<br>Motivo: ${esc(d.revoked_reason)}<br><a href="/doc/${d.id}/constancia" target="_blank"><b>Descargar constancia de revocación (PDF)</b></a></div>` : '';
  const revForm = d.revoked_at ? '' : `<details class="card"><summary><b>Revocar este documento</b></summary>
<p class="mut">El documento y sus pruebas se conservan intactos. Queda registrado que dejó de estar vigente, con fecha, hora y motivo, y la página de verificación lo mostrará. <b>No se puede deshacer.</b>${done ? '' : ' Como todavía faltan firmas, los links pendientes dejarán de funcionar.'}</p>
<form method="post" action="/doc/${d.id}/revocar"><label>Motivo de la revocación (obligatorio)</label><textarea name="reason" rows="3" maxlength="500" required></textarea>
<label class="consent"><input type="checkbox" required><span>Entiendo que la revocación no se puede deshacer.</span></label>
<button class="btn red">Revocar documento</button></form></details>`;
  res.send(page(d.title, `<p><a href="/">← Volver</a></p><h1>${esc(d.title)}</h1>${revBanner}
<p>${d.revoked_at ? '<span class="badge b-rev">Revocado</span>' : (done ? '<span class="badge b-ok">Todas las firmas completas</span>' : '<span class="badge b-pend">Esperando firmas</span>')} <span class="mut">Creado ${fmtDate(d.created_at)}</span></p>
<p><a class="btn sec small" href="/doc/${d.id}/original" target="_blank">Ver original</a> ${done ? `<a class="btn small" href="/doc/${d.id}/firmado">Descargar PDF firmado</a>` : ''}</p>
<h2>Firmantes</h2>${rows}
<div class="card mut">Huella SHA-256 del original:<br><span class="mono">${d.sha256}</span>${done ? `<br><br>Huella del PDF firmado:<br><span class="mono">${d.final_sha256}</span>` : ''}</div>
${revForm}
<form method="post" action="/doc/${d.id}/eliminar" onsubmit="return confirm('¿Eliminar este documento y sus firmas? No se puede deshacer.')"><button class="btn red small">Eliminar documento</button></form>`, req, { admin: true }));
});
app.post('/doc/:id/revocar', requireAdmin, (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).send('No existe');
  const reason = String(req.body.reason || '').trim().slice(0, 500);
  if (reason.length < 3) return res.status(400).send('Falta el motivo de la revocación.');
  if (!d.revoked_at) {
    db.prepare('UPDATE documents SET revoked_at=?, revoked_reason=?, revoked_ip=? WHERE id=? AND revoked_at IS NULL')
      .run(new Date().toISOString(), reason, clientIp(req), d.id);
  }
  res.redirect('/doc/' + d.id);
});
app.get('/doc/:id/constancia', requireAdmin, async (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
  if (!d || !d.revoked_at) return res.status(404).send('Este documento no está revocado');
  const sg = db.prepare('SELECT name,signed_name,status,signed_at FROM signers WHERE doc_id=? ORDER BY id').all(d.id);
  const out = await buildRevocationPdf(d, sg, baseUrl(req));
  res.set('Content-Disposition', 'attachment; filename="constancia-de-revocacion.pdf"');
  res.type('pdf').send(out);
});
app.get('/doc/:id/original', requireAdmin, (req, res) => {
  const f = path.join(DATA_DIR, 'docs', path.basename(req.params.id) + '.pdf');
  if (!fs.existsSync(f)) return res.status(404).send('No existe');
  res.type('pdf').sendFile(f);
});
app.get('/doc/:id/firmado', requireAdmin, (req, res) => {
  const d = db.prepare('SELECT title FROM documents WHERE id=?').get(req.params.id);
  const f = path.join(DATA_DIR, 'final', path.basename(req.params.id) + '.pdf');
  if (!d || !fs.existsSync(f)) return res.status(404).send('Todavía no está firmado');
  res.download(f, (d.title.replace(/[^\w\- ]+/g, '').trim() || 'documento') + ' - firmado.pdf');
});
app.post('/doc/:id/eliminar', requireAdmin, (req, res) => {
  const id = path.basename(req.params.id);
  db.prepare('DELETE FROM signers WHERE doc_id=?').run(id);
  db.prepare('DELETE FROM documents WHERE id=?').run(id);
  for (const d of ['docs', 'final']) fs.rmSync(path.join(DATA_DIR, d, id + '.pdf'), { force: true });
  res.redirect('/');
});

// ---------- pantalla del firmante (celular) ----------
const SIGN_CSS = `
body{background:#eef0f8}main{padding:12px;max-width:640px}
.pdfwrap{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#fff}
.pdfwrap iframe{width:100%;height:60vh;border:0;display:block}
#pad{width:100%;height:200px;border:2px dashed #8a90b8;border-radius:10px;background:#fff;touch-action:none;display:block}
.consent{display:flex;gap:10px;align-items:flex-start;margin:14px 0;font-size:15px}.consent input{width:22px;height:22px;margin-top:2px;flex:none}
`;
function loadSigner(token) {
  return db.prepare('SELECT s.*, d.title, d.status dstatus, d.revoked_at FROM signers s JOIN documents d ON d.id=s.doc_id WHERE s.token=?').get(String(token));
}
app.get('/firmar/:token', (req, res) => {
  const s = loadSigner(req.params.token);
  if (!s) return res.status(404).send(page('Link no válido', '<div class="card"><h1>Link no válido</h1><p>Este link no existe o fue eliminado.</p></div>', req));
  if (s.revoked_at) {
    return res.send(page('Documento revocado', `<div class="card"><h1>Documento revocado</h1><p><b>${esc(s.title)}</b></p><p>Este documento fue revocado el ${fmtDate(s.revoked_at)} y ya no está vigente${s.status === 'firmado' ? '. Tu firma quedó registrada, pero el documento dejó de tener efecto como firmado' : ', por lo que ya no se puede firmar'}.</p><p class="mut">Si tenés dudas, comunicate con quien te lo envió.</p></div>`, req));
  }
  if (!s.opened_at) db.prepare('UPDATE signers SET opened_at=? WHERE id=?').run(new Date().toISOString(), s.id);
  if (s.status === 'firmado') {
    return res.send(page('Ya firmado', `<div class="card"><h1>✓ Ya firmaste este documento</h1><p><b>${esc(s.title)}</b></p><p class="mut">Firmado el ${fmtDate(s.signed_at)}.</p>${s.dstatus === 'firmado' ? `<p><a class="btn" href="/firmar/${s.token}/descargar">Descargar copia firmada</a></p>` : '<p class="mut">Cuando firmen todas las partes vas a poder descargar la copia final desde este mismo link.</p>'}</div>`, req));
  }
  const body = `<div class="card"><h1 style="margin-top:0">Hola ${esc(s.name)}</h1><p>Te pidieron firmar: <b>${esc(s.title)}</b></p>
<div class="pdfwrap" id="pages"><p class="mut" style="padding:16px">Cargando documento…</p></div>
<p class="mut">Podés hacer zoom con los dedos. <a href="/firmar/${s.token}/pdf" target="_blank">Abrir el PDF aparte</a></p></div>
<div class="card" id="formcard"><h2>Tu firma</h2>
<label>Escribí tu nombre completo</label><input type="text" id="nm" value="${esc(s.name)}" autocomplete="name">
<label>Firmá con el dedo en el recuadro</label>
<canvas id="pad"></canvas>
<p><button type="button" class="btn sec small" id="clr">Borrar y volver a firmar</button></p>
<label class="consent"><input type="checkbox" id="ok"><span>Leí el documento y acepto firmarlo electrónicamente. Entiendo que quedan registrados mi firma, fecha, hora, dirección IP y dispositivo.</span></label>
<button class="btn" id="go" style="width:100%" disabled>Revisar mi firma</button></div>
<div class="card" id="review" style="display:none"><h2>Revisá tu firma</h2>
<p class="mut">Así va a quedar tu firma. Si no te gusta, podés rehacerla.</p>
<img id="prev" alt="Tu firma" style="width:100%;max-height:220px;object-fit:contain;border:1px solid var(--line);border-radius:10px;background:#fff">
<p><b id="prevname"></b></p>
<div id="msg"></div>
<button class="btn" id="confirm" style="width:100%">Confirmar y firmar</button>
<p><button type="button" class="btn sec" id="redo" style="width:100%">Rehacer mi firma</button></p></div>`;
  const script = `<script type="module">
(async function(){
  var box=document.getElementById('pages');
  try{
    var pdfjs=await import('/pdfjs/pdf.min.mjs');
    pdfjs.GlobalWorkerOptions.workerSrc='/pdfjs/pdf.worker.min.mjs';
    var doc=await pdfjs.getDocument({url:'/firmar/${s.token}/pdf'}).promise;
    box.innerHTML='';
    var w=box.clientWidth,d=Math.min(window.devicePixelRatio||1,2.5);
    for(var n=1;n<=doc.numPages;n++){
      var pg=await doc.getPage(n),v0=pg.getViewport({scale:1}),sc=w/v0.width,v=pg.getViewport({scale:sc*d});
      var cv=document.createElement('canvas');cv.width=v.width;cv.height=v.height;
      cv.style.cssText='width:100%;display:block;border-bottom:6px solid #eef0f8';
      box.appendChild(cv);
      await pg.render({canvasContext:cv.getContext('2d'),viewport:v}).promise;
    }
  }catch(e){
    box.innerHTML='<p style="padding:16px">No se pudo mostrar el documento acá. <a href="/firmar/${s.token}/pdf" target="_blank">Tocá para abrirlo</a>.</p>';
  }
})();
(function(){
var c=document.getElementById('pad'),ctx=c.getContext('2d'),drawn=false,down=false,last=null,pts=0;
function size(){var r=c.getBoundingClientRect();if(!r.width)return;var d=window.devicePixelRatio||1;var img=drawn?c.toDataURL():null;c.width=r.width*d;c.height=r.height*d;ctx.scale(d,d);ctx.lineWidth=2.6;ctx.lineCap='round';ctx.lineJoin='round';ctx.strokeStyle='#111';if(img){var i=new Image();i.onload=function(){ctx.drawImage(i,0,0,r.width,r.height)};i.src=img}}
size();window.addEventListener('resize',size);
function pos(e){var r=c.getBoundingClientRect();return{x:e.clientX-r.left,y:e.clientY-r.top}}
c.addEventListener('pointerdown',function(e){e.preventDefault();c.setPointerCapture(e.pointerId);down=true;last=pos(e);ctx.beginPath();ctx.arc(last.x,last.y,1.2,0,6.3);ctx.fill();});
c.addEventListener('pointermove',function(e){if(!down)return;e.preventDefault();var p=pos(e);ctx.beginPath();ctx.moveTo(last.x,last.y);ctx.lineTo(p.x,p.y);ctx.stroke();last=p;pts++;drawn=true;upd();});
function end(){down=false}
c.addEventListener('pointerup',end);c.addEventListener('pointercancel',end);c.addEventListener('pointerleave',end);
function clearPad(){var r=c.getBoundingClientRect();ctx.clearRect(0,0,r.width,r.height);drawn=false;pts=0;upd();}
document.getElementById('clr').onclick=clearPad;
var ok=document.getElementById('ok'),go=document.getElementById('go'),nm=document.getElementById('nm'),msg=document.getElementById('msg');
var formcard=document.getElementById('formcard'),review=document.getElementById('review'),confirmBtn=document.getElementById('confirm');
function upd(){go.disabled=!(drawn&&pts>8&&ok.checked&&nm.value.trim().length>1)}
ok.onchange=upd;nm.oninput=upd;
var shot=null;
go.onclick=function(){
  shot=c.toDataURL('image/png');
  document.getElementById('prev').src=shot;
  document.getElementById('prevname').textContent=nm.value.trim();
  msg.innerHTML='';
  formcard.style.display='none';review.style.display='block';
  review.scrollIntoView({behavior:'smooth',block:'start'});
};
document.getElementById('redo').onclick=function(){
  review.style.display='none';formcard.style.display='block';
  drawn=false;pts=0;size();upd();shot=null;
  formcard.scrollIntoView({behavior:'smooth',block:'start'});
};
confirmBtn.onclick=function(){
  confirmBtn.disabled=true;confirmBtn.textContent='Firmando…';msg.innerHTML='';
  fetch('/firmar/${s.token}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:nm.value.trim(),consent:true,signature:shot})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})
  .then(function(x){if(x.ok){location.reload()}else{throw new Error(x.j.error||'Error')}})
  .catch(function(e){msg.innerHTML='<div class="err">'+e.message+'</div>';confirmBtn.disabled=false;confirmBtn.textContent='Confirmar y firmar'});
};
})();
</script>`;
  res.send(page('Firmar documento', body, req, { css: SIGN_CSS, script }));
});

app.get('/firmar/:token/pdf', (req, res) => {
  const s = loadSigner(req.params.token);
  if (!s) return res.status(404).send('No existe');
  if (s.revoked_at) return res.status(410).send('Documento revocado');
  res.set('Cache-Control', 'private, no-store');
  res.type('pdf').sendFile(path.join(DATA_DIR, 'docs', path.basename(s.doc_id) + '.pdf'));
});
app.get('/firmar/:token/descargar', (req, res) => {
  const s = loadSigner(req.params.token);
  const f = s && path.join(DATA_DIR, 'final', path.basename(s.doc_id) + '.pdf');
  if (!s || s.status !== 'firmado' || s.dstatus !== 'firmado' || !fs.existsSync(f)) return res.status(404).send('Todavía no disponible');
  res.download(f, (s.title.replace(/[^\w\- ]+/g, '').trim() || 'documento') + ' - firmado.pdf');
});

app.post('/firmar/:token', async (req, res) => {
  try {
    const s = loadSigner(req.params.token);
    if (!s) return res.status(404).json({ error: 'Link no válido' });
    if (s.revoked_at) return res.status(409).json({ error: 'Este documento fue revocado y ya no se puede firmar' });
    if (s.status === 'firmado') return res.status(409).json({ error: 'Ya firmaste este documento' });
    const { name, consent, signature } = req.body || {};
    if (consent !== true) return res.status(400).json({ error: 'Tenés que aceptar el consentimiento' });
    const nm = String(name || '').trim().slice(0, 120);
    if (nm.length < 2) return res.status(400).json({ error: 'Escribí tu nombre' });
    const m = /^data:image\/png;base64,([A-Za-z0-9+/=]+)$/.exec(String(signature || ''));
    if (!m) return res.status(400).json({ error: 'Firma inválida' });
    const png = Buffer.from(m[1], 'base64');
    if (png.length < 600 || png.length > 1500000 || png.slice(1, 4).toString() !== 'PNG') return res.status(400).json({ error: 'Firma inválida o vacía' });
    const upd = db.prepare("UPDATE signers SET status='firmado', signed_at=?, signed_name=?, ip=?, ua=?, signature_png=? WHERE id=? AND status='pendiente'")
      .run(new Date().toISOString(), nm, clientIp(req), String(req.get('user-agent') || '').slice(0, 300), png, s.id);
    if (!upd.changes) return res.status(409).json({ error: 'Ya firmaste este documento' });
    const pend = db.prepare("SELECT COUNT(*) n FROM signers WHERE doc_id=? AND status!='firmado'").get(s.doc_id).n;
    if (pend === 0) await buildFinal(s.doc_id, baseUrl(req));
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'No se pudo registrar la firma. Probá de nuevo.' });
  }
});

// ---------- PDF final + expediente de evidencias ----------
const safe = (t) => String(t ?? '').replace(/[^\x20-\x7E\xA0-\xFF]/g, '?');
function wrap(font, text, size, maxW) {
  const out = [];
  for (const para of safe(text).split('\n')) {
    let line = '';
    for (const word of para.split(' ')) {
      const test = line ? line + ' ' + word : word;
      if (font.widthOfTextAtSize(test, size) <= maxW) line = test;
      else {
        if (line) out.push(line);
        let w = word;
        while (font.widthOfTextAtSize(w, size) > maxW) {
          let k = w.length;
          while (k > 1 && font.widthOfTextAtSize(w.slice(0, k), size) > maxW) k--;
          out.push(w.slice(0, k)); w = w.slice(k);
        }
        line = w;
      }
    }
    out.push(line);
  }
  return out;
}
async function buildFinal(docId, base) {
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(docId);
  const sg = db.prepare('SELECT * FROM signers WHERE doc_id=? ORDER BY id').all(docId);
  const orig = fs.readFileSync(path.join(DATA_DIR, 'docs', docId + '.pdf'));
  const pdf = await PDFDocument.load(orig, { ignoreEncryption: true });
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const mono = await pdf.embedFont(StandardFonts.Courier);
  const W = 595, H = 842, M = 48, ink = rgb(0.12, 0.13, 0.44);

  // Hoja de firmas
  let page = pdf.addPage([W, H]); let y = H - M;
  page.drawText('Hoja de firmas', { x: M, y: y - 8, size: 22, font: bold, color: ink }); y -= 38;
  // QR para consultar el estado actual del documento (vigente / revocado)
  const verifyUrl = `${base}/v/${d.id}`;
  const qrImg = await pdf.embedPng(await QRCode.toBuffer(verifyUrl, { margin: 1, width: 240, errorCorrectionLevel: 'M' }));
  page.drawImage(qrImg, { x: W - M - 76, y: H - M - 66, width: 76, height: 76 });
  ['Escanea para consultar', 'el estado de este documento'].forEach((t, i) => {
    page.drawText(t, { x: W - M - 76 - 8 - font.widthOfTextAtSize(t, 8), y: H - M - 30 - i * 11, size: 8, font, color: rgb(0.35, 0.37, 0.5) });
  });
  for (const l of wrap(font, 'Documento: ' + d.title, 11, W - 2 * M - 170)) { page.drawText(l, { x: M, y, size: 11, font }); y -= 15; }
  y = Math.min(y - 10, H - M - 66 - 14); // deja lugar para el QR
  for (const s of sg) {
    if (y < 190) { page = pdf.addPage([W, H]); y = H - M; }
    page.drawRectangle({ x: M, y: y - 150, width: W - 2 * M, height: 150, borderColor: rgb(0.78, 0.8, 0.88), borderWidth: 1 });
    const img = await pdf.embedPng(s.signature_png);
    const maxW = 230, maxH = 90; const sc = Math.min(maxW / img.width, maxH / img.height);
    page.drawImage(img, { x: M + 14, y: y - 110, width: img.width * sc, height: img.height * sc });
    page.drawLine({ start: { x: M + 14, y: y - 118 }, end: { x: M + 14 + 250, y: y - 118 }, thickness: 0.7, color: rgb(0.3, 0.3, 0.3) });
    page.drawText(safe(s.signed_name || s.name), { x: M + 14, y: y - 132, size: 12, font: bold });
    page.drawText('Firmado: ' + safe(fmtDate(s.signed_at)), { x: M + 290, y: y - 40, size: 10, font });
    page.drawText('IP: ' + safe(s.ip), { x: M + 290, y: y - 56, size: 10, font });
    page.drawText('Firma electronica simple', { x: M + 290, y: y - 72, size: 10, font });
    y -= 168;
  }

  // Expediente de evidencias
  page = pdf.addPage([W, H]); y = H - M;
  page.drawText('Expediente de evidencias', { x: M, y: y - 8, size: 22, font: bold, color: ink }); y -= 40;
  const line = (label, value, f = font) => {
    page.drawText(label, { x: M, y, size: 10, font: bold, color: rgb(0.35, 0.37, 0.5) }); y -= 13;
    for (const l of wrap(f, value, f === mono ? 9 : 10.5, W - 2 * M)) { if (y < M) { page = pdf.addPage([W, H]); y = H - M; } page.drawText(l, { x: M, y, size: f === mono ? 9 : 10.5, font: f }); y -= 13; }
    y -= 6;
  };
  line('Documento', d.title);
  line('Huella SHA-256 del documento original (antes de firmar)', d.sha256, mono);
  line('Creado', fmtDate(d.created_at));
  line('Consulta del estado actual (vigente / revocado)', verifyUrl, mono);
  for (const s of sg) {
    if (y < 150) { page = pdf.addPage([W, H]); y = H - M; }
    page.drawLine({ start: { x: M, y: y + 6 }, end: { x: W - M, y: y + 6 }, thickness: 0.5, color: rgb(0.8, 0.8, 0.85) }); y -= 8;
    line('Firmante', `${s.signed_name || s.name}${s.contact ? ' (' + s.contact + ')' : ''}`);
    line('Fecha y hora de la firma', fmtDate(s.signed_at) + '  (UTC: ' + s.signed_at + ')');
    line('Direccion IP', s.ip || '-');
    line('Dispositivo / navegador', s.ua || '-');
    line('Metodo', 'Firma electronica simple. El firmante abrio un enlace unico y privado, leyo el documento, acepto firmar electronicamente y dibujo su firma.');
    line('Huella SHA-256 de la firma dibujada', sha256(s.signature_png), mono);
  }
  pdf.setTitle(safe(d.title) + ' (firmado)');
  pdf.setProducer(BRAND);
  const out = Buffer.from(await pdf.save());
  fs.writeFileSync(path.join(DATA_DIR, 'final', docId + '.pdf'), out);
  db.prepare("UPDATE documents SET status='firmado', completed_at=?, final_sha256=? WHERE id=?").run(new Date().toISOString(), sha256(out), docId);
}

// ---------- constancia de revocación ----------
async function buildRevocationPdf(d, sg, base) {
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const mono = await pdf.embedFont(StandardFonts.Courier);
  const W = 595, H = 842, M = 56, red = rgb(0.56, 0.11, 0.09);
  let page = pdf.addPage([W, H]); let y = H - M;
  page.drawText('Constancia de revocacion', { x: M, y: y - 8, size: 22, font: bold, color: red }); y -= 44;
  const line = (label, value, f = font) => {
    page.drawText(safe(label), { x: M, y, size: 10, font: bold, color: rgb(0.35, 0.37, 0.5) }); y -= 14;
    const size = f === mono ? 9 : 11;
    for (const l of wrap(f, value, size, W - 2 * M)) { if (y < M) { page = pdf.addPage([W, H]); y = H - M; } page.drawText(l, { x: M, y, size, font: f }); y -= 14; }
    y -= 8;
  };
  const signed = sg.filter((s) => s.status === 'firmado').length;
  line('Documento', d.title);
  line('Estado antes de la revocacion', d.status === 'firmado' ? `Firmado por todas las partes el ${fmtDate(d.completed_at)}` : `Incompleto: ${signed} de ${sg.length} firmas`);
  line('Fecha y hora de la revocacion', `${fmtDate(d.revoked_at)}  (UTC: ${d.revoked_at})`);
  line('Motivo declarado', d.revoked_reason);
  line('Direccion IP desde la que se registro', d.revoked_ip || '-');
  for (const s of sg) line('Firmante', `${s.signed_name || s.name} - ${s.status === 'firmado' ? 'firmo el ' + fmtDate(s.signed_at) : 'no llego a firmar'}`);
  line('Huella SHA-256 del documento original', d.sha256, mono);
  if (d.final_sha256) line('Huella SHA-256 del PDF firmado', d.final_sha256, mono);
  line('Consulta del estado en linea', `${base}/v/${d.id}`, mono);
  y -= 6;
  for (const l of wrap(font, 'Esta constancia deja registro de que el documento dejo de estar vigente a partir de la fecha indicada. La revocacion no modifica ni elimina el documento firmado ni sus pruebas, que se conservan intactos. Sus efectos legales dependen de lo establecido en el contrato y en la normativa aplicable.', 9.5, W - 2 * M)) { page.drawText(l, { x: M, y, size: 9.5, font, color: rgb(0.3, 0.3, 0.3) }); y -= 13; }
  pdf.setTitle('Constancia de revocacion - ' + safe(d.title));
  pdf.setProducer(BRAND);
  return Buffer.from(await pdf.save());
}

// ---------- página pública de estado (la abre el QR) ----------
app.get('/v/:id', (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(String(req.params.id));
  if (!d) return res.status(404).send(page('No encontrado', '<div class="card"><h1>Documento no encontrado</h1></div>', req));
  const sg = db.prepare('SELECT signed_name,name,status,signed_at FROM signers WHERE doc_id=? ORDER BY id').all(d.id);
  const state = d.revoked_at
    ? `<div class="err"><b>REVOCADO.</b> Este documento fue revocado el ${fmtDate(d.revoked_at)} y <b>ya no está vigente</b>.</div>`
    : (d.status === 'firmado' ? '<div class="ok"><b>VIGENTE.</b> Firmado por todas las partes y sin revocaciones registradas.</div>' : '<div class="err" style="background:#fff0d6;color:#8a5200"><b>PENDIENTE.</b> Todavía faltan firmas.</div>');
  res.send(page('Estado del documento', `<h1>Estado del documento</h1>${state}<div class="card"><b>${esc(d.title)}</b><ul>${sg.map((s) => `<li>${esc(s.signed_name || s.name)} — ${s.status === 'firmado' ? 'firmó el ' + fmtDate(s.signed_at) : 'sin firmar'}</li>`).join('')}</ul>${d.final_sha256 ? `<div class="mut">Huella SHA-256 del PDF firmado:<br><span class="mono">${d.final_sha256}</span></div>` : ''}</div><p class="mut">Para comprobar que tu copia del PDF no fue modificada, usá <a href="/verificar">verificar documento</a>.</p>`, req, { admin: isAdmin(req) }));
});

// ---------- verificación pública ----------
app.get('/verificar', (req, res) => {
  res.send(page('Verificar documento', `<h1>Verificar un documento firmado</h1><div class="card"><p>Subí un PDF firmado y comprobamos si es exactamente el que se emitió acá (sin modificaciones).</p><form method="post" action="/verificar" enctype="multipart/form-data"><input type="file" name="pdf" accept="application/pdf" required><p><button class="btn">Verificar</button></p></form></div>`, req, { admin: isAdmin(req) }));
});
app.post('/verificar', upload.single('pdf'), (req, res) => {
  let result;
  if (!req.file) result = '<div class="err">Subí un archivo.</div>';
  else {
    const h = sha256(req.file.buffer);
    const d = db.prepare('SELECT * FROM documents WHERE final_sha256=?').get(h);
    const rec = d ? null : recibos.verifyByHash(h);
    if (rec) {
      result = rec;
    } else if (d) {
      const sg = db.prepare('SELECT signed_name,name,signed_at FROM signers WHERE doc_id=? ORDER BY id').all(d.id);
      const revNote = d.revoked_at ? `<div class="err"><b>REVOCADO.</b> Este documento fue revocado el ${fmtDate(d.revoked_at)} y <b>ya no está vigente</b>.</div>` : '<div class="ok"><b>VIGENTE.</b> No hay revocaciones registradas.</div>';
      result = `<div class="ok"><b>✓ Documento auténtico.</b> Es el PDF firmado emitido por ${esc(BRAND)} y no fue modificado.</div>${revNote}<div class="card"><b>${esc(d.title)}</b><ul>${sg.map((s) => `<li>${esc(s.signed_name || s.name)} — ${fmtDate(s.signed_at)}</li>`).join('')}</ul><div class="mut">Huella SHA-256:<br><span class="mono">${h}</span></div></div>`;
    } else {
      result = `<div class="err"><b>No coincide.</b> Este archivo no es un PDF firmado emitido acá, o fue modificado después de firmarse.</div><div class="mut">Huella SHA-256:<br><span class="mono">${h}</span></div>`;
    }
  }
  res.send(page('Verificar documento', `<h1>Resultado</h1>${result}<p><a href="/verificar">Verificar otro</a></p>`, req, { admin: isAdmin(req) }));
});

// ---------- recibos de seña (ver recibos.js) ----------
const recibos = require('./recibos')({ app, db, page, esc, fmtDate, requireAdmin, isAdmin, upload, baseUrl, clientIp, sha256, newId, newToken, safe, wrap, DATA_DIR, BRAND });

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 500).send(err.code === 'LIMIT_FILE_SIZE' ? `El archivo supera los ${MAX_MB} MB.` : 'Error del servidor');
});

app.listen(PORT, () => console.log(`${BRAND} funcionando en http://localhost:${PORT}`));
