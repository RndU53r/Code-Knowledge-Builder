const axios = require('axios');

class BaseRepo {
  save(item) {
    return item;
  }
}

class OrderRepo extends BaseRepo {
  save(item) {
    axios.post('http://billing/charge', item);
    this.db.query(`SELECT * FROM orders WHERE id = ${item.id}`);
    return super.save(item);
  }
}

module.exports = { OrderRepo, BaseRepo };
