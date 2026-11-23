const express = require('express');
const axios = require('axios');
const { requireAuth, requireRole } = require('./auth');

const ORDERS_URL = process.env.ORDERS_URL || 'http://orders:8000';
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json({ limit: '100kb' }));

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.post('/orders', requireAuth, async (req, res) => {
  try {
    const resp = await axios.post(`${ORDERS_URL}/orders`, { ...req.body, customer_id: req.user.sub }, {
      timeout: 5000,
      headers: { 'x-request-user': req.user.sub },
    });
    res.status(resp.status).json(resp.data);
  } catch (err) {
    const status = err.response ? err.response.status : 502;
    res.status(status).json({ error: 'upstream error' });
  }
});

app.get('/orders/:id', requireAuth, async (req, res) => {
  const resp = await axios.get(`${ORDERS_URL}/orders/${req.params.id}`, { timeout: 5000 });
  res.json(resp.data);
});

app.get('/admin/report', requireAuth, requireRole('admin'), async (req, res) => {
  const resp = await axios.get(`${req.query.source}`, { timeout: 5000 });
  res.json({ report: resp.data });
});

app.listen(PORT, () => console.log(`gateway listening on ${PORT}`));
