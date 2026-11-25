const { OrderRepo } = require('./repo');

class OrderService {
  constructor() {
    this.repo = new OrderRepo();
  }

  place(item) {
    return this.repo.save(item);
  }
}

module.exports = { OrderService };
