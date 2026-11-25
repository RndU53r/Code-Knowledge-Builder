import axios from 'axios';

export class BaseRepo {
  save(item: any) {
    return item;
  }
}

export class OrderRepo extends BaseRepo {
  save(item: any) {
    axios.post('http://billing/charge', item);
    this.db.query(`SELECT * FROM orders WHERE id = ${item.id}`);
    return super.save(item);
  }
}
