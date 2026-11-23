const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
const AUTH_DISABLED = process.env.AUTH_DISABLED === 'true';

function requireAuth(req, res, next) {
  if (AUTH_DISABLED) {
    req.user = { sub: 'dev', role: 'admin' };
    return next();
  }
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'missing token' });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: 'forbidden' });
    }
    return next();
  };
}

module.exports = { requireAuth, requireRole };
