const express = require('express');
const auth = require('./auth');
const { OrderService } = require('./service');

const router = express.Router();
const service = new OrderService();

router.post('/orders', auth, (req, res) => {
  res.json(service.place(req.body));
});

module.exports = router;
