const jwt = require('jsonwebtoken');

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

function signUserToken({ userId, email }) {
  const secret = requireEnv('JWT_SECRET');
  return jwt.sign({ sub: String(userId), email, typ: 'user' }, secret, { expiresIn: '7d' });
}

function signAdminToken() {
  const secret = requireEnv('JWT_SECRET');
  return jwt.sign({ sub: 'admin', typ: 'admin' }, secret, { expiresIn: '7d' });
}

function authFromRequest(req) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) return header.slice('Bearer '.length);
  if (req.cookies && req.cookies.token) return req.cookies.token;
  return null;
}

function requireUser(req, res, next) {
  try {
    const token = authFromRequest(req);
    if (!token) return res.status(401).json({ error: 'unauthorized' });
    const secret = requireEnv('JWT_SECRET');
    const payload = jwt.verify(token, secret);
    if (payload.typ !== 'user') return res.status(403).json({ error: 'forbidden' });
    req.user = { id: payload.sub, email: payload.email };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

function requireAdmin(req, res, next) {
  try {
    const token = authFromRequest(req);
    if (!token) return res.status(401).json({ error: 'unauthorized' });
    const secret = requireEnv('JWT_SECRET');
    const payload = jwt.verify(token, secret);
    if (payload.typ !== 'admin') return res.status(403).json({ error: 'forbidden' });
    next();
  } catch (e) {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

module.exports = { signUserToken, signAdminToken, requireUser, requireAdmin };
