'use strict';
// Recibos de seña: emisión con firma del administrador, envío y revocación.
// Todo lo de administración exige sesión de administrador. Solo son públicos:
//   /recibo/:token  (descarga del PDF por quien recibió el link)
//   /r/:id          (estado vigente/revocado, lo abre el QR del recibo)
const fs = require('fs');
const path = require('path');
const { PDFDocument, StandardFonts, rgb, degrees } = require('pdf-lib');
const QRCode = require('qrcode');

module.exports = function initRecibos(ctx) {
  const { app, db, page, esc, fmtDate, requireAdmin, upload, baseUrl, clientIp, sha256, newId, newToken, safe, wrap, DATA_DIR, BRAND } = ctx;

  fs.mkdirSync(path.join(DATA_DIR, 'receipts'), { recursive: true });
  db.exec(`
CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY, number INTEGER NOT NULL UNIQUE, token TEXT NOT NULL UNIQUE,
  payer_name TEXT NOT NULL, payer_doc TEXT, payer_phone TEXT,
  amount_cents INTEGER NOT NULL, currency TEXT NOT NULL, paid_at TEXT NOT NULL,
  method TEXT, concept TEXT NOT NULL, doc_id TEXT, notes TEXT, sha256 TEXT,
  created_at TEXT NOT NULL,
  revoked_at TEXT, revoked_reason TEXT, revoked_ip TEXT
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
`);

  // ---------- ajustes del emisor ----------
  const getS = (k, def = '') => { const r = db.prepare('SELECT value FROM settings WHERE key=?').get(k); return r ? r.value : def; };
  const setS = (k, v) => db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k, String(v));
  const issuer = () => ({
    name: getS('issuer_name', process.env.ISSUER_NAME || BRAND),
    taxid: getS('issuer_id', process.env.ISSUER_ID || ''),
    address: getS('issuer_address', ''),
    label: getS('signer_label', ''),
  });
  function signatureFile() {
    for (const f of [path.join(DATA_DIR, 'firma-admin.png'), path.join(DATA_DIR, 'firma-admin.jpg'), path.join(__dirname, 'assets', 'firma-admin.png')]) {
      if (fs.existsSync(f)) return f;
    }
    return null;
  }
  async function embedSignature(pdf) {
    const f = signatureFile();
    if (!f) return null;
    const b = fs.readFileSync(f);
    return b[0] === 0xff ? pdf.embedJpg(b) : pdf.embedPng(b);
  }


  // ---------- utilidades ----------
  const pad = (n) => String(n).padStart(8, '0');
  const nf = new Intl.NumberFormat('es-AR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const money = (c, cur) => (cur === 'USD' ? 'US$ ' : '$ ') + nf.format(c / 100);
  const fmtDay = (ymd) => { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(ymd || ''); return m ? `${m[3]}/${m[2]}/${m[1]}` : String(ymd || ''); };
  const todayAR = () => new Date().toLocaleDateString('en-CA', { timeZone: 'America/Argentina/Buenos_Aires' });
  const wrapLines = (font, text, size, w) => String(text ?? '').split(/\r?\n/).flatMap((p) => wrap(font, p, size, w));

  function parseAmount(s) {
    s = String(s || '').replace(/[^\d.,]/g, '');
    if (!s) return NaN;
    let intPart, dec = '';
    if (s.includes(',')) {
      const i = s.lastIndexOf(',');
      intPart = s.slice(0, i).replace(/\./g, ''); dec = s.slice(i + 1).replace(/\./g, '');
    } else if ((s.match(/\./g) || []).length === 1 && /\.\d{1,2}$/.test(s)) {
      const i = s.lastIndexOf('.'); intPart = s.slice(0, i); dec = s.slice(i + 1);
    } else intPart = s.replace(/\./g, '');
    if (dec.length > 2) return NaN;
    const cents = Math.round(Number((intPart || '0') + '.' + (dec || '0')) * 100);
    return Number.isFinite(cents) ? cents : NaN;
  }

  // número a letras (español)
  const U = ['cero', 'uno', 'dos', 'tres', 'cuatro', 'cinco', 'seis', 'siete', 'ocho', 'nueve', 'diez', 'once', 'doce', 'trece', 'catorce', 'quince', 'dieciséis', 'diecisiete', 'dieciocho', 'diecinueve', 'veinte', 'veintiuno', 'veintidós', 'veintitrés', 'veinticuatro', 'veinticinco', 'veintiséis', 'veintisiete', 'veintiocho', 'veintinueve'];
  const T = ['', '', '', 'treinta', 'cuarenta', 'cincuenta', 'sesenta', 'setenta', 'ochenta', 'noventa'];
  const C = ['', 'ciento', 'doscientos', 'trescientos', 'cuatrocientos', 'quinientos', 'seiscientos', 'setecientos', 'ochocientos', 'novecientos'];
  const apocope = (s) => s.replace(/veintiuno$/, 'veintiún').replace(/uno$/, 'un');
  function below1000(n) {
    if (n === 100) return 'cien';
    const out = []; const c = Math.floor(n / 100), r = n % 100;
    if (c) out.push(C[c]);
    if (r) { if (r < 30) out.push(U[r]); else { const t = Math.floor(r / 10), u = r % 10; out.push(u ? `${T[t]} y ${U[u]}` : T[t]); } }
    return out.join(' ');
  }
  function below1e6(n) {
    const th = Math.floor(n / 1000), r = n % 1000; const out = [];
    if (th) out.push(th === 1 ? 'mil' : apocope(below1000(th)) + ' mil');
    if (r) out.push(below1000(r));
    return out.join(' ');
  }
  function words(n) {
    if (n === 0) return 'cero';
    const mill = Math.floor(n / 1e6), r = n % 1e6; const out = [];
    if (mill) out.push(mill === 1 ? 'un millón' : apocope(below1e6(mill)) + ' millones');
    if (r) out.push(below1e6(r));
    return out.join(' ') + (mill && !r ? ' de' : '');
  }
  function amountWords(cents, cur) {
    const whole = Math.floor(cents / 100), cc = String(cents % 100).padStart(2, '0');
    const noun = cur === 'USD' ? (whole === 1 ? 'dólar estadounidense' : 'dólares estadounidenses') : (whole === 1 ? 'peso' : 'pesos');
    const w = apocope(words(whole));
    const txt = `${w} ${noun} con ${cc}/100`;
    return txt.charAt(0).toUpperCase() + txt.slice(1);
  }

  // ---------- PDF del recibo ----------
  async function buildReceiptPdf(r, base) {
    const iss = issuer();
    const pdf = await PDFDocument.create();
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
    const ital = await pdf.embedFont(StandardFonts.HelveticaOblique);
    const mono = await pdf.embedFont(StandardFonts.Courier);
    const W = 595, H = 842, M = 48;
    const ink = rgb(0.12, 0.13, 0.44), grey = rgb(0.35, 0.37, 0.5), white = rgb(1, 1, 1);
    const pg = pdf.addPage([W, H]);
    const right = (t, y, size, f, color) => pg.drawText(safe(t), { x: W - M - f.widthOfTextAtSize(safe(t), size), y, size, font: f, color });

    // cabecera
    pg.drawRectangle({ x: 0, y: H - 104, width: W, height: 104, color: ink });
    let ty = H - 44;
    for (const l of wrapLines(bold, iss.name, 19, W - 2 * M - 170)) { pg.drawText(safe(l), { x: M, y: ty, size: 19, font: bold, color: white }); ty -= 22; }
    const sub = [iss.taxid && 'CUIT/DNI: ' + iss.taxid, iss.address].filter(Boolean).join('  ·  ');
    if (sub) for (const l of wrapLines(font, sub, 9.5, W - 2 * M - 170)) { pg.drawText(safe(l), { x: M, y: ty, size: 9.5, font, color: rgb(0.82, 0.84, 1) }); ty -= 12; }
    right('N° ' + pad(r.number), H - 44, 17, bold, white);
    right('Emitido: ' + fmtDay(new Date(r.created_at).toLocaleDateString('en-CA', { timeZone: 'America/Argentina/Buenos_Aires' })), H - 62, 10, font, rgb(0.82, 0.84, 1));

    pg.drawText('RECIBO DE SEÑA', { x: M, y: H - 150, size: 26, font: bold, color: ink });

    // monto
    const boxTop = H - 172, boxH = 92;
    pg.drawRectangle({ x: M, y: boxTop - boxH, width: W - 2 * M, height: boxH, color: rgb(0.95, 0.96, 1), borderColor: rgb(0.78, 0.8, 0.9), borderWidth: 1 });
    pg.drawText('SEÑA RECIBIDA', { x: M + 16, y: boxTop - 20, size: 9, font: bold, color: grey });
    pg.drawText(safe(money(r.amount_cents, r.currency)), { x: M + 16, y: boxTop - 52, size: 30, font: bold, color: ink });
    let wy = boxTop - 70;
    for (const l of wrapLines(ital, amountWords(r.amount_cents, r.currency), 10, W - 2 * M - 32).slice(0, 2)) { pg.drawText(safe(l), { x: M + 16, y: wy, size: 10, font: ital, color: rgb(0.2, 0.2, 0.3) }); wy -= 12; }

    // datos
    let y = boxTop - boxH - 30;
    const field = (label, value) => {
      if (!value) return;
      pg.drawText(safe(label), { x: M, y, size: 9, font: bold, color: grey }); y -= 14;
      for (const l of wrapLines(font, value, 11, W - 2 * M)) { if (y < 260) break; pg.drawText(safe(l), { x: M, y, size: 11, font }); y -= 14; }
      y -= 8;
    };
    const row2 = (l1, v1, l2, v2) => {
      pg.drawText(safe(l1), { x: M, y, size: 9, font: bold, color: grey });
      pg.drawText(safe(l2), { x: M + 250, y, size: 9, font: bold, color: grey }); y -= 14;
      pg.drawText(safe(v1 || '-'), { x: M, y, size: 11, font });
      pg.drawText(safe(v2 || '-'), { x: M + 250, y, size: 11, font }); y -= 22;
    };
    field('RECIBÍ DE', r.payer_name + (r.payer_doc ? '  (DNI/CUIT: ' + r.payer_doc + ')' : ''));
    field('EN CONCEPTO DE', r.concept);
    row2('FECHA DEL PAGO', fmtDay(r.paid_at), 'FORMA DE PAGO', r.method);
    if (r.doc_id) {
      const d = db.prepare('SELECT title FROM documents WHERE id=?').get(r.doc_id);
      if (d) field('DOCUMENTO VINCULADO', d.title);
    }
    field('OBSERVACIONES', r.notes);

    // firma del administrador
    const sig = await embedSignature(pdf);
    if (sig) {
      const sc = Math.min(200 / sig.width, 92 / sig.height);
      pg.drawImage(sig, { x: M + 6, y: 176, width: sig.width * sc, height: sig.height * sc });
    }
    pg.drawLine({ start: { x: M, y: 172 }, end: { x: M + 230, y: 172 }, thickness: 0.8, color: rgb(0.3, 0.3, 0.3) });
    pg.drawText(safe(iss.label || iss.name), { x: M, y: 157, size: 11, font: bold });
    if (iss.taxid) pg.drawText(safe('CUIT/DNI: ' + iss.taxid), { x: M, y: 144, size: 9.5, font });
    pg.drawText('Emisor del recibo', { x: M, y: iss.taxid ? 132 : 144, size: 9, font, color: grey });

    // QR de verificación
    const verifyUrl = `${base}/r/${r.id}`;
    const qr = await pdf.embedPng(await QRCode.toBuffer(verifyUrl, { margin: 1, width: 260, errorCorrectionLevel: 'M' }));
    pg.drawImage(qr, { x: W - M - 84, y: 140, width: 84, height: 84 });
    const qt = 'Verificá este recibo';
    pg.drawText(qt, { x: W - M - 84 + (84 - font.widthOfTextAtSize(qt, 8)) / 2, y: 129, size: 8, font, color: grey });
    pg.drawText(r.id, { x: W - M - 84 + (84 - mono.widthOfTextAtSize(r.id, 7.5)) / 2, y: 118, size: 7.5, font: mono, color: grey });

    // pie
    pg.drawLine({ start: { x: M, y: 98 }, end: { x: W - M, y: 98 }, thickness: 0.5, color: rgb(0.8, 0.8, 0.85) });
    const foot = `Comprobante electrónico de recepción de seña, emitido con firma electrónica simple del emisor. No es una factura ni un comprobante fiscal. Emitido el ${fmtDate(r.created_at)}. Podés consultar si sigue vigente con el código QR o en ${verifyUrl}`;
    let fy = 84;
    for (const l of wrapLines(font, foot, 8, W - 2 * M)) { pg.drawText(safe(l), { x: M, y: fy, size: 8, font, color: grey }); fy -= 10.5; }

    pdf.setTitle(`Recibo de seña N° ${pad(r.number)}`);
    pdf.setProducer(BRAND);
    return Buffer.from(await pdf.save());
  }

  // Copia marcada como REVOCADO (el original guardado nunca se modifica)
  async function stampRevoked(buf, r) {
    const pdf = await PDFDocument.load(buf);
    const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
    const red = rgb(0.7, 0.15, 0.12);
    for (const p of pdf.getPages()) {
      const { width, height } = p.getSize();
      const size = 96, text = 'REVOCADO', w = bold.widthOfTextAtSize(text, size), a = (32 * Math.PI) / 180, h = size * 0.7;
      p.drawText(text, {
        x: width / 2 - (w / 2) * Math.cos(a) + (h / 2) * Math.sin(a),
        y: height / 2 - (w / 2) * Math.sin(a) - (h / 2) * Math.cos(a),
        size, font: bold, color: red, opacity: 0.28, rotate: degrees(32),
      });
      p.drawRectangle({ x: 0, y: height - 22, width, height: 22, color: red });
      const msg = safe(`RECIBO REVOCADO el ${fmtDate(r.revoked_at)} - ya no esta vigente`);
      p.drawText(msg, { x: (width - bold.widthOfTextAtSize(msg, 10)) / 2, y: height - 15, size: 10, font: bold, color: rgb(1, 1, 1) });
    }
    return Buffer.from(await pdf.save());
  }

  async function buildRevocationPdf(r, base) {
    const pdf = await PDFDocument.create();
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
    const mono = await pdf.embedFont(StandardFonts.Courier);
    const W = 595, H = 842, M = 56, red = rgb(0.56, 0.11, 0.09);
    let pg = pdf.addPage([W, H]); let y = H - M;
    pg.drawText('Constancia de revocacion de recibo', { x: M, y: y - 8, size: 20, font: bold, color: red }); y -= 44;
    const line = (label, value, f = font) => {
      pg.drawText(safe(label), { x: M, y, size: 10, font: bold, color: rgb(0.35, 0.37, 0.5) }); y -= 14;
      const size = f === mono ? 9 : 11;
      for (const l of wrapLines(f, value, size, W - 2 * M)) { if (y < 150) { pg = pdf.addPage([W, H]); y = H - M; } pg.drawText(safe(l), { x: M, y, size, font: f }); y -= 14; }
      y -= 8;
    };
    line('Recibo', `Recibo de seña N° ${pad(r.number)} emitido el ${fmtDate(r.created_at)}`);
    line('Recibido de', r.payer_name);
    line('Importe', `${money(r.amount_cents, r.currency)} (${amountWords(r.amount_cents, r.currency)})`);
    line('Concepto', r.concept);
    line('Fecha y hora de la revocacion', `${fmtDate(r.revoked_at)}  (UTC: ${r.revoked_at})`);
    line('Motivo declarado', r.revoked_reason);
    line('Direccion IP desde la que se registro', r.revoked_ip || '-');
    line('Huella SHA-256 del recibo original', r.sha256 || '-', mono);
    line('Consulta del estado en linea', `${base}/r/${r.id}`, mono);
    y -= 4;
    for (const l of wrapLines(font, 'Esta constancia deja registro de que el recibo dejo de estar vigente a partir de la fecha indicada. La revocacion no modifica ni elimina el recibo original, que se conserva intacto junto con sus pruebas. Sus efectos legales dependen de lo acordado entre las partes y de la normativa aplicable.', 9.5, W - 2 * M)) { pg.drawText(safe(l), { x: M, y, size: 9.5, font, color: rgb(0.3, 0.3, 0.3) }); y -= 13; }
    const sig = await embedSignature(pdf);
    if (sig && y > 150) {
      const sc = Math.min(150 / sig.width, 60 / sig.height);
      pg.drawImage(sig, { x: M, y: y - 80, width: sig.width * sc, height: sig.height * sc });
      pg.drawLine({ start: { x: M, y: y - 84 }, end: { x: M + 200, y: y - 84 }, thickness: 0.7, color: rgb(0.3, 0.3, 0.3) });
      pg.drawText(safe(issuer().label || issuer().name), { x: M, y: y - 97, size: 10, font: bold });
    }
    pdf.setTitle(`Constancia de revocacion - Recibo ${pad(r.number)}`);
    pdf.setProducer(BRAND);
    return Buffer.from(await pdf.save());
  }

  // ---------- acceso a archivos ----------
  const receiptFile = (id) => path.join(DATA_DIR, 'receipts', path.basename(id) + '.pdf');
  const getReceipt = (id) => db.prepare('SELECT * FROM receipts WHERE id=?').get(String(id));
  async function currentPdf(r) {
    const buf = fs.readFileSync(receiptFile(r.id));
    return r.revoked_at ? stampRevoked(buf, r) : buf;
  }
  const publicLink = (req, r) => `${baseUrl(req)}/recibo/${r.token}`;

  // ---------- envío ----------
  const waLink = (phone, text) => {
    const digits = String(phone || '').replace(/\D/g, '');
    return digits ? `https://wa.me/${digits}?text=${encodeURIComponent(text)}` : null;
  };
  const flash = (req) => (req.query.m ? `<div class="ok">${esc(req.query.m)}</div>` : '') + (req.query.e ? `<div class="err">${esc(req.query.e)}</div>` : '');
  const badge = (r) => (r.revoked_at ? '<span class="badge b-rev">Revocado</span>' : '<span class="badge b-ok">Vigente</span>');

  // ================= ADMIN =================
  app.get('/recibos', requireAdmin, (req, res) => {
    const rows = db.prepare('SELECT * FROM receipts ORDER BY number DESC').all();
    const tot = db.prepare('SELECT currency, SUM(amount_cents) s, COUNT(*) n FROM receipts WHERE revoked_at IS NULL GROUP BY currency').all();
    const totHtml = tot.length ? `<p class="mut">Señas vigentes: ${tot.map((t) => `<b>${esc(money(t.s, t.currency))}</b> (${t.n})`).join(' · ')}</p>` : '';
    const body = rows.map((r) => `<tr><td><a href="/recibos/${r.id}"><b>N° ${pad(r.number)}</b></a><div class="mut">${fmtDay(r.paid_at)}</div></td><td>${esc(r.payer_name)}<div class="mut">${esc(r.concept.slice(0, 60))}</div></td><td style="white-space:nowrap">${esc(money(r.amount_cents, r.currency))}</td><td>${badge(r)}</td></tr>`).join('');
    res.send(page('Recibos de seña', `<h1>Recibos de seña</h1>${flash(req)}<p><a class="btn" href="/recibos/nuevo">+ Nuevo recibo de seña</a></p>${totHtml}<div class="card">${rows.length ? `<table><tr><th>Recibo</th><th>Recibido de</th><th>Importe</th><th>Estado</th></tr>${body}</table>` : '<p class="mut">Todavía no emitiste ningún recibo.</p>'}</div>`, req, { admin: true }));
  });

  app.get('/recibos/nuevo', requireAdmin, (req, res) => {
    const docs = db.prepare('SELECT id,title FROM documents ORDER BY created_at DESC LIMIT 200').all();
    const q = req.query;
    const noSig = !signatureFile() ? '<div class="err">Todavía no cargaste tu firma: los recibos saldrían sin firma. Cargala en <a href="/ajustes">Ajustes</a>.</div>' : '';
    const opt = (v, l, sel) => `<option value="${esc(v)}"${sel === v ? ' selected' : ''}>${esc(l)}</option>`;
    res.send(page('Nuevo recibo', `<h1>Nuevo recibo de seña</h1>${noSig}${flash(req)}
<form method="post" action="/recibos/nuevo" class="card">
<div class="row"><div><label>Recibido de (nombre y apellido)</label><input type="text" name="payer_name" value="${esc(q.payer_name || '')}" required maxlength="120"></div>
<div><label>DNI o CUIT (opcional)</label><input type="text" name="payer_doc" value="${esc(q.payer_doc || '')}" maxlength="40"></div></div>
<label>WhatsApp del cliente (para enviarle el recibo)</label><input type="text" name="payer_phone" value="${esc(q.payer_phone || '')}" placeholder="+54 9 11 ..." maxlength="40">
<div class="row"><div><label>Importe de la seña</label><input type="text" name="amount" inputmode="decimal" value="${esc(q.amount || '')}" placeholder="Ej: 150.000 o 1.500,50" required></div>
<div><label>Moneda</label><select name="currency" style="width:100%;padding:12px;border:1px solid #c9cde0;border-radius:8px;font-size:16px;background:#fff">${opt('ARS', 'Pesos argentinos ($)', q.currency)}${opt('USD', 'Dólares (US$)', q.currency)}</select></div></div>
<div class="row"><div><label>Fecha del pago</label><input type="date" name="paid_at" value="${esc(q.paid_at || todayAR())}" required style="width:100%;padding:12px;border:1px solid #c9cde0;border-radius:8px;font-size:16px"></div>
<div><label>Forma de pago</label><select name="method" style="width:100%;padding:12px;border:1px solid #c9cde0;border-radius:8px;font-size:16px;background:#fff">${['Efectivo', 'Transferencia bancaria', 'Mercado Pago', 'Tarjeta', 'Cheque', 'Otra'].map((m) => opt(m, m, q.method)).join('')}</select></div></div>
<label>En concepto de</label><input type="text" name="concept" value="${esc(q.concept || '')}" placeholder="Ej: Seña por reserva de..." required maxlength="250">
<label>Documento firmado vinculado (opcional)</label><select name="doc_id" style="width:100%;padding:12px;border:1px solid #c9cde0;border-radius:8px;font-size:16px;background:#fff"><option value="">— Ninguno —</option>${docs.map((d) => opt(d.id, d.title, q.doc_id)).join('')}</select>
<label>Observaciones (opcional)</label><textarea name="notes" rows="3" maxlength="400">${esc(q.notes || '')}</textarea>
<p><button class="btn">Crear recibo firmado</button></p></form>`, req, { admin: true }));
  });

  app.post('/recibos/nuevo', requireAdmin, async (req, res) => {
    const b = req.body || {};
    const back = (e) => res.redirect('/recibos/nuevo?' + new URLSearchParams({ ...Object.fromEntries(Object.entries(b).map(([k, v]) => [k, String(v).slice(0, 400)])), e }).toString());
    const clean = (s, n) => String(s || '').trim().slice(0, n);
    const payer_name = clean(b.payer_name, 120), concept = clean(b.concept, 250);
    if (!payer_name || !concept) return back('Falta el nombre o el concepto.');
    const cents = parseAmount(b.amount);
    if (!Number.isFinite(cents) || cents <= 0 || cents > 1e12) return back('El importe no es válido. Ejemplo: 150.000 o 1.500,50');
    const currency = b.currency === 'USD' ? 'USD' : 'ARS';
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(b.paid_at || ''))) return back('La fecha del pago no es válida.');
    const doc_id = clean(b.doc_id, 40);
    if (doc_id && !db.prepare('SELECT 1 FROM documents WHERE id=?').get(doc_id)) return back('El documento vinculado no existe.');
    const id = newId();
    let r;
    try {
      db.prepare(`INSERT INTO receipts (id,number,token,payer_name,payer_doc,payer_phone,amount_cents,currency,paid_at,method,concept,doc_id,notes,created_at)
        VALUES (?, (SELECT COALESCE(MAX(number),0)+1 FROM receipts), ?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(id, newToken(), payer_name, clean(b.payer_doc, 40), clean(b.payer_phone, 40), cents, currency, b.paid_at, clean(b.method, 40), concept, doc_id || null, clean(b.notes, 400), new Date().toISOString());
      r = getReceipt(id);
      const buf = await buildReceiptPdf(r, baseUrl(req));
      fs.writeFileSync(receiptFile(id), buf);
      db.prepare('UPDATE receipts SET sha256=? WHERE id=?').run(sha256(buf), id);
    } catch (e) {
      console.error(e);
      db.prepare('DELETE FROM receipts WHERE id=?').run(id);
      return back('No se pudo crear el recibo. Probá de nuevo.');
    }
    let msg = 'Recibo creado y firmado.';
    res.redirect(`/recibos/${id}?m=` + encodeURIComponent(msg));
  });

  app.get('/recibos/:id', requireAdmin, (req, res) => {
    const r = getReceipt(req.params.id);
    if (!r) return res.status(404).send('No existe');
    const url = publicLink(req, r), iss = issuer();
    const msg = `Hola ${r.payer_name}, te envío el recibo de seña N° ${pad(r.number)} por ${money(r.amount_cents, r.currency)}. Podés verlo y descargarlo acá: ${url}`;
    const wa = waLink(r.payer_phone, msg);
    const d = r.doc_id ? db.prepare('SELECT id,title FROM documents WHERE id=?').get(r.doc_id) : null;

    const revBanner = r.revoked_at ? `<div class="err"><b>Recibo REVOCADO</b> el ${fmtDate(r.revoked_at)}.<br>Motivo: ${esc(r.revoked_reason)}<br><a href="/recibos/${r.id}/constancia" target="_blank"><b>Descargar constancia de revocación (PDF)</b></a></div>` : '';
    const revWa = r.revoked_at ? waLink(r.payer_phone, `Hola ${r.payer_name}, te aviso que el recibo de seña N° ${pad(r.number)} fue REVOCADO el ${fmtDate(r.revoked_at)}. Motivo: ${r.revoked_reason}. Podés ver el estado acá: ${baseUrl(req)}/r/${r.id}`) : null;
    const actions = `<div class="card"><h2>Enviar al pagador</h2>
${r.revoked_at ? '<p class="mut">Este recibo está revocado: el link público muestra la copia marcada como REVOCADO.</p>' : ''}
<div class="link"><input type="text" readonly value="${esc(url)}" onclick="this.select()" style="flex:1 1 240px">
<button type="button" class="btn small sec" onclick="navigator.clipboard.writeText('${esc(url)}');this.textContent='¡Copiado!'">Copiar link</button></div>
<p class="row" style="margin-bottom:0">
${!r.revoked_at && wa ? `<a class="btn wa small" target="_blank" rel="noopener" href="${esc(wa)}">Enviar por WhatsApp</a>` : ''}
${r.revoked_at && revWa ? `<a class="btn wa small" target="_blank" rel="noopener" href="${esc(revWa)}">Avisar la revocación por WhatsApp</a>` : ''}
</p>
${!r.payer_phone ? '<p class="mut">No cargaste el WhatsApp del cliente: copiá el link y mandalo como prefieras.</p>' : ''}</div>`;
    const revForm = r.revoked_at ? '' : `<details class="card"><summary><b>Revocar este recibo</b></summary>
<p class="mut">El recibo original y sus pruebas se conservan intactos. Queda registrado que dejó de estar vigente, con fecha, hora y motivo; el link y el QR pasan a mostrar REVOCADO. <b>No se puede deshacer.</b></p>
<form method="post" action="/recibos/${r.id}/revocar"><label>Motivo de la revocación (obligatorio)</label><textarea name="reason" rows="3" maxlength="500" required></textarea>
<label class="consent"><input type="checkbox" required><span>Entiendo que la revocación no se puede deshacer.</span></label>
<button class="btn red">Revocar recibo</button></form></details>`;
    res.send(page(`Recibo ${pad(r.number)}`, `<p><a href="/recibos">← Volver</a></p><h1>Recibo de seña N° ${pad(r.number)} ${badge(r)}</h1>${flash(req)}${revBanner}
<div class="card"><table>
<tr><th>Importe</th><td><b style="font-size:20px">${esc(money(r.amount_cents, r.currency))}</b><div class="mut">${esc(amountWords(r.amount_cents, r.currency))}</div></td></tr>
<tr><th>Recibido de</th><td>${esc(r.payer_name)}${r.payer_doc ? ` <span class="mut">(${esc(r.payer_doc)})</span>` : ''}<div class="mut">${esc(r.payer_phone || '')}</div></td></tr>
<tr><th>Concepto</th><td>${esc(r.concept)}</td></tr>
<tr><th>Pago</th><td>${fmtDay(r.paid_at)} · ${esc(r.method || '-')}</td></tr>
${d ? `<tr><th>Documento</th><td><a href="/doc/${d.id}">${esc(d.title)}</a></td></tr>` : ''}
${r.notes ? `<tr><th>Observaciones</th><td>${esc(r.notes)}</td></tr>` : ''}
<tr><th>Emitido</th><td>${fmtDate(r.created_at)}</td></tr></table></div>
<p><a class="btn small" href="/recibos/${r.id}/pdf" target="_blank">Ver PDF${r.revoked_at ? ' (marcado REVOCADO)' : ''}</a> ${r.revoked_at ? `<a class="btn small sec" href="/recibos/${r.id}/original" target="_blank">Ver original sin marca</a>` : ''}</p>
${actions}
<div class="card mut">Huella SHA-256 del recibo original:<br><span class="mono">${esc(r.sha256)}</span></div>${revForm}`, req, { admin: true }));
  });

  app.get('/recibos/:id/pdf', requireAdmin, async (req, res) => {
    const r = getReceipt(req.params.id);
    if (!r || !fs.existsSync(receiptFile(r.id))) return res.status(404).send('No existe');
    res.set('Content-Disposition', `inline; filename="recibo-${pad(r.number)}${r.revoked_at ? '-REVOCADO' : ''}.pdf"`);
    res.type('pdf').send(await currentPdf(r));
  });
  app.get('/recibos/:id/original', requireAdmin, (req, res) => {
    const r = getReceipt(req.params.id);
    if (!r || !fs.existsSync(receiptFile(r.id))) return res.status(404).send('No existe');
    res.set('Content-Disposition', `inline; filename="recibo-${pad(r.number)}-original.pdf"`);
    res.type('pdf').sendFile(receiptFile(r.id));
  });
  app.get('/recibos/:id/constancia', requireAdmin, async (req, res) => {
    const r = getReceipt(req.params.id);
    if (!r || !r.revoked_at) return res.status(404).send('Este recibo no está revocado');
    res.set('Content-Disposition', `attachment; filename="constancia-revocacion-recibo-${pad(r.number)}.pdf"`);
    res.type('pdf').send(await buildRevocationPdf(r, baseUrl(req)));
  });


  app.post('/recibos/:id/revocar', requireAdmin, async (req, res) => {
    const r = getReceipt(req.params.id);
    if (!r) return res.status(404).send('No existe');
    const b = req.body || {};
    const reason = String(b.reason || '').trim().slice(0, 500);
    if (reason.length < 3) return res.redirect(`/recibos/${r.id}?e=` + encodeURIComponent('Falta el motivo de la revocación.'));
    db.prepare('UPDATE receipts SET revoked_at=?, revoked_reason=?, revoked_ip=? WHERE id=? AND revoked_at IS NULL')
      .run(new Date().toISOString(), reason, clientIp(req), r.id);
    let msg = 'Recibo revocado.';
    res.redirect(`/recibos/${r.id}?m=` + encodeURIComponent(msg));
  });

  // ---------- ajustes: datos del emisor y firma ----------
  app.get('/ajustes/firma', requireAdmin, (req, res) => {
    const f = signatureFile();
    if (!f) return res.status(404).send('Sin firma');
    res.set('Cache-Control', 'no-store');
    res.type(f.endsWith('.jpg') ? 'jpg' : 'png').sendFile(f);
  });
  app.get('/ajustes', requireAdmin, (req, res) => {
    const iss = issuer();
    res.send(page('Ajustes', `<h1>Ajustes de recibos</h1>${flash(req)}
<form method="post" action="/ajustes" enctype="multipart/form-data" class="card">
<h2>Datos que salen en el recibo</h2>
<label>Nombre o razón social del emisor</label><input type="text" name="issuer_name" value="${esc(iss.name)}" maxlength="120" required>
<div class="row"><div><label>CUIT o DNI (opcional)</label><input type="text" name="issuer_id" value="${esc(iss.taxid)}" maxlength="40"></div>
<div><label>Domicilio (opcional)</label><input type="text" name="issuer_address" value="${esc(iss.address)}" maxlength="160"></div></div>
<label>Aclaración debajo de la firma (opcional)</label><input type="text" name="signer_label" value="${esc(iss.label)}" placeholder="Ej: Martin Troccoli" maxlength="120">
<h2 style="margin-top:22px">Tu firma</h2>
${signatureFile() ? '<p class="mut">Esta es la firma que se estampa en los recibos:</p><div style="background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px;max-width:320px"><img src="/ajustes/firma" alt="Tu firma" style="width:100%;display:block"></div>' : '<div class="err">Todavía no hay firma cargada.</div>'}
<label>Cambiar la firma (imagen PNG o JPG, mejor con fondo transparente)</label><input type="file" name="firma" accept="image/png,image/jpeg">
<p class="mut">La firma que subís acá se guarda en el servidor, en la carpeta privada de datos.</p>
<p><button class="btn">Guardar</button></p></form>`, req, { admin: true }));
  });
  app.post('/ajustes', requireAdmin, upload.single('firma'), async (req, res) => {
    const b = req.body || {};
    const clean = (s, n) => String(s || '').trim().slice(0, n);
    const name = clean(b.issuer_name, 120);
    if (!name) return res.redirect('/ajustes?e=' + encodeURIComponent('El nombre del emisor es obligatorio.'));
    if (req.file && req.file.size) {
      const buf = req.file.buffer;
      const isPng = buf.slice(0, 4).toString('hex') === '89504e47', isJpg = buf.slice(0, 3).toString('hex') === 'ffd8ff';
      if (!isPng && !isJpg) return res.redirect('/ajustes?e=' + encodeURIComponent('La firma tiene que ser una imagen PNG o JPG.'));
      if (buf.length > 1500000) return res.redirect('/ajustes?e=' + encodeURIComponent('La imagen es muy pesada (máximo 1,5 MB).'));
      try { const t = await PDFDocument.create(); isPng ? await t.embedPng(buf) : await t.embedJpg(buf); }
      catch { return res.redirect('/ajustes?e=' + encodeURIComponent('No se pudo leer esa imagen.')); }
      for (const f of ['firma-admin.png', 'firma-admin.jpg']) fs.rmSync(path.join(DATA_DIR, f), { force: true });
      fs.writeFileSync(path.join(DATA_DIR, isPng ? 'firma-admin.png' : 'firma-admin.jpg'), buf);
    }
    setS('issuer_name', name); setS('issuer_id', clean(b.issuer_id, 40)); setS('issuer_address', clean(b.issuer_address, 160)); setS('signer_label', clean(b.signer_label, 120));
    res.redirect('/ajustes?m=' + encodeURIComponent('Ajustes guardados. Los recibos nuevos usarán estos datos.'));
  });

  // ================= PÚBLICO =================
  app.get('/recibo/:token', async (req, res) => {
    const r = db.prepare('SELECT * FROM receipts WHERE token=?').get(String(req.params.token));
    if (!r || !fs.existsSync(receiptFile(r.id))) return res.status(404).send(page('Link no válido', '<div class="card"><h1>Link no válido</h1><p>Este link no existe.</p></div>', req));
    res.set('Cache-Control', 'private, no-store');
    res.set('Content-Disposition', `inline; filename="recibo-${pad(r.number)}${r.revoked_at ? '-REVOCADO' : ''}.pdf"`);
    res.type('pdf').send(await currentPdf(r));
  });

  app.get('/r/:id', (req, res) => {
    const r = getReceipt(req.params.id);
    if (!r) return res.status(404).send(page('No encontrado', '<div class="card"><h1>Recibo no encontrado</h1></div>', req));
    res.send(page('Estado del recibo', `<h1>Estado del recibo</h1>${stateHtml(r)}<div class="card"><b>Recibo de seña N° ${pad(r.number)}</b><ul><li>Importe: ${esc(money(r.amount_cents, r.currency))}</li><li>Recibido de: ${esc(r.payer_name)}</li><li>Concepto: ${esc(r.concept)}</li><li>Fecha del pago: ${fmtDay(r.paid_at)}</li><li>Emitido por: ${esc(issuer().name)}</li></ul><div class="mut">Huella SHA-256 del recibo original:<br><span class="mono">${esc(r.sha256)}</span></div></div><p class="mut">Para comprobar que tu copia del PDF no fue modificada, usá <a href="/verificar">verificar documento</a>.</p>`, req, { admin: ctx.isAdmin(req) }));
  });
  const stateHtml = (r) => (r.revoked_at
    ? `<div class="err"><b>REVOCADO.</b> Este recibo fue revocado el ${fmtDate(r.revoked_at)} y <b>ya no está vigente</b>.</div>`
    : '<div class="ok"><b>VIGENTE.</b> Recibo emitido y sin revocaciones registradas.</div>');

  // lo usa /verificar: si el PDF subido es un recibo emitido acá
  return {
    verifyByHash(h) {
      const r = db.prepare('SELECT * FROM receipts WHERE sha256=?').get(h);
      if (!r) return null;
      return `<div class="ok"><b>✓ Recibo auténtico.</b> Es el recibo de seña N° ${pad(r.number)} emitido por ${esc(issuer().name)} y no fue modificado.</div>${stateHtml(r)}<div class="card"><b>${esc(money(r.amount_cents, r.currency))}</b> — ${esc(r.payer_name)}<br><span class="mut">${esc(r.concept)} · ${fmtDay(r.paid_at)}</span><div class="mut" style="margin-top:8px">Huella SHA-256:<br><span class="mono">${h}</span></div></div>`;
    },
  };
};
