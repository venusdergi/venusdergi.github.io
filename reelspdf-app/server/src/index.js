require('dotenv').config();

const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { z } = require('zod');

const { init, run, get, all } = require('./db');
const { signUserToken, signAdminToken, requireUser, requireAdmin } = require('./auth');
const { getSupabase } = require('./supabase');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowed = (process.env.CORS_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  if (origin && (allowed.includes('*') || allowed.includes(origin))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

const publicDir = path.join(__dirname, '..', '..', 'public');
const uploadsDir = path.join(__dirname, '..', '..', 'uploads');

app.use(express.static(publicDir));

const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== 'application/pdf') return cb(new Error('Only PDF allowed'));
    cb(null, true);
  },
  limits: { fileSize: 25 * 1024 * 1024 }
});

app.get('/api/me', requireUser, async (req, res) => {
  res.json({ id: req.user.id, email: req.user.email });
});

app.post('/api/auth/register', async (req, res) => {
  const schema = z.object({ email: z.string().email(), password: z.string().min(6).max(72) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' });

  const { email, password } = parsed.data;
  const existing = await get('SELECT id FROM users WHERE email = ?', [email]);
  if (existing) return res.status(409).json({ error: 'email_taken' });

  const passwordHash = await bcrypt.hash(password, 10);
  const now = new Date().toISOString();
  const result = await run('INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)', [email, passwordHash, now]);

  const token = signUserToken({ userId: result.lastID, email });
  res.json({ ok: true, token });
});

app.post('/api/auth/login', async (req, res) => {
  const schema = z.object({ email: z.string().email(), password: z.string().min(6).max(72) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' });

  const { email, password } = parsed.data;
  const user = await get('SELECT id, email, password_hash FROM users WHERE email = ?', [email]);
  if (!user) return res.status(401).json({ error: 'user_not_found' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'wrong_password' });

  const token = signUserToken({ userId: user.id, email: user.email });
  res.json({ ok: true, token });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.post('/api/admin/login', async (req, res) => {
  const schema = z.object({ email: z.string().email(), password: z.string().min(1).max(200) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' });

  const { email, password } = parsed.data;
  if (email !== process.env.ADMIN_EMAIL || password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  const token = signAdminToken();
  res.json({ ok: true, token });
});

app.get('/api/reels', async (req, res) => {
  const rows = await all('SELECT id, title, description, pdf_url, created_at FROM reels ORDER BY id DESC');
  res.json({ reels: rows.map(r => ({ ...r, pdf_url: r.pdf_url })) });
});

app.get('/api/reels/public', async (req, res) => {
  const rows = await all('SELECT id, title, description, pdf_url, created_at FROM reels ORDER BY id DESC');
  res.json({ reels: rows.map(r => ({ ...r, pdf_url: r.pdf_url })) });
});

app.get('/api/reels/:reelId/pages/:page/reactions', async (req, res) => {
  const reelId = Number(req.params.reelId);
  const page = Number(req.params.page);
  if (!Number.isFinite(reelId) || !Number.isFinite(page)) return res.status(400).json({ error: 'invalid_input' });

  const likesRow = await get(
    'SELECT COUNT(1) as c FROM reel_likes WHERE reel_id = ? AND page = ?',
    [reelId, page]
  );
  const likes = Number(likesRow && likesRow.c ? likesRow.c : 0);

  let liked = false;
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    try {
      // reuse existing auth middleware logic by verifying token inline
      const jwt = require('jsonwebtoken');
      const secret = process.env.JWT_SECRET;
      const payload = jwt.verify(auth.slice('Bearer '.length), secret);
      if (payload && payload.typ === 'user') {
        const mine = await get(
          'SELECT 1 as x FROM reel_likes WHERE reel_id = ? AND page = ? AND user_id = ? LIMIT 1',
          [reelId, page, Number(payload.sub)]
        );
        liked = !!mine;
      }
    } catch {}
  }

  res.json({ likes, liked });
});

app.post('/api/reels/:reelId/pages/:page/like', requireUser, async (req, res) => {
  const reelId = Number(req.params.reelId);
  const page = Number(req.params.page);
  if (!Number.isFinite(reelId) || !Number.isFinite(page)) return res.status(400).json({ error: 'invalid_input' });

  const userId = Number(req.user.id);
  const existing = await get(
    'SELECT id FROM reel_likes WHERE reel_id = ? AND page = ? AND user_id = ?',
    [reelId, page, userId]
  );

  if (existing) {
    await run('DELETE FROM reel_likes WHERE id = ?', [existing.id]);
  } else {
    const now = new Date().toISOString();
    await run(
      'INSERT INTO reel_likes (reel_id, page, user_id, created_at) VALUES (?, ?, ?, ?)',
      [reelId, page, userId, now]
    );
  }

  const likesRow = await get(
    'SELECT COUNT(1) as c FROM reel_likes WHERE reel_id = ? AND page = ?',
    [reelId, page]
  );
  const likes = Number(likesRow && likesRow.c ? likesRow.c : 0);
  const liked = !existing;
  res.json({ ok: true, likes, liked });
});

app.get('/api/reels/:reelId/pages/:page/comments', async (req, res) => {
  const reelId = Number(req.params.reelId);
  const page = Number(req.params.page);
  if (!Number.isFinite(reelId) || !Number.isFinite(page)) return res.status(400).json({ error: 'invalid_input' });

  const rows = await all(
    `
      SELECT c.id, c.text, c.created_at, u.email as user
      FROM reel_comments c
      JOIN users u ON u.id = c.user_id
      WHERE c.reel_id = ? AND c.page = ?
      ORDER BY c.id ASC
    `,
    [reelId, page]
  );

  res.json({ comments: rows });
});

app.post('/api/reels/:reelId/pages/:page/comments', requireUser, async (req, res) => {
  const reelId = Number(req.params.reelId);
  const page = Number(req.params.page);
  if (!Number.isFinite(reelId) || !Number.isFinite(page)) return res.status(400).json({ error: 'invalid_input' });

  const schema = z.object({ text: z.string().min(1).max(500) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' });

  const userId = Number(req.user.id);
  const now = new Date().toISOString();
  const result = await run(
    'INSERT INTO reel_comments (reel_id, page, user_id, text, created_at) VALUES (?, ?, ?, ?, ?)',
    [reelId, page, userId, parsed.data.text, now]
  );

  const row = await get(
    `
      SELECT c.id, c.text, c.created_at, u.email as user
      FROM reel_comments c
      JOIN users u ON u.id = c.user_id
      WHERE c.id = ?
    `,
    [result.lastID]
  );

  res.json({ ok: true, comment: row });
});

app.get('/api/admin/reels', requireAdmin, async (req, res) => {
  const rows = await all('SELECT id, title, description, pdf_path, pdf_url, created_at FROM reels ORDER BY id DESC');
  res.json({ reels: rows });
});

app.post('/api/admin/reels', requireAdmin, upload.single('pdf'), async (req, res) => {
  const schema = z.object({ title: z.string().min(1).max(80), description: z.string().min(0).max(500) });
  const parsed = schema.safeParse({ title: req.body.title, description: req.body.description ?? '' });
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' });
  if (!req.file) return res.status(400).json({ error: 'missing_pdf' });

  const { title, description } = parsed.data;
  const now = new Date().toISOString();

  const supabase = getSupabase();
  const bucket = process.env.SUPABASE_STORAGE_BUCKET;
  if (!bucket) return res.status(500).json({ error: 'missing_storage_bucket' });

  const safe = String(req.file.originalname || 'file.pdf').replace(/[^a-zA-Z0-9._-]/g, '_');
  const objectPath = `pdf/${Date.now()}_${safe}`;

  const { error: upErr } = await supabase.storage
    .from(bucket)
    .upload(objectPath, req.file.buffer, { contentType: 'application/pdf', upsert: false });

  if (upErr) return res.status(500).json({ error: 'upload_failed' });

  const { data: pub } = supabase.storage.from(bucket).getPublicUrl(objectPath);
  const pdfUrl = pub && pub.publicUrl ? pub.publicUrl : null;
  if (!pdfUrl) return res.status(500).json({ error: 'public_url_failed' });

  const result = await run(
    'INSERT INTO reels (title, description, pdf_path, pdf_url, created_at) VALUES (?, ?, ?, ?, ?)',
    [title, description, objectPath, pdfUrl, now]
  );

  res.json({ ok: true, id: result.lastID });
});

app.delete('/api/admin/reels/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });

  const reel = await get('SELECT id, pdf_path FROM reels WHERE id = ?', [id]);
  if (!reel) return res.status(404).json({ error: 'not_found' });

  const supabase = getSupabase();
  const bucket = process.env.SUPABASE_STORAGE_BUCKET;
  if (!bucket) return res.status(500).json({ error: 'missing_storage_bucket' });

  const paths = [];
  if (reel.pdf_path) paths.push(reel.pdf_path);

  if (paths.length) {
    const { error: delErr } = await supabase.storage.from(bucket).remove(paths);
    if (delErr) return res.status(500).json({ error: 'storage_delete_failed' });
  }

  await run('DELETE FROM reels WHERE id = ?', [id]);
  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'server_error' });
});

const port = Number(process.env.PORT || 5179);
init().then(() => {
  app.listen(port, () => {
    console.log(`ReelsPDF server running on http://localhost:${port}`);
  });
});
