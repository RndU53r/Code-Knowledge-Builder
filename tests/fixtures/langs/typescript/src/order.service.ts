import { Injectable } from '@nestjs/common';
import { OrderRepo } from './order.repo';

@Injectable()
export class OrderService {
  constructor(private readonly repo: OrderRepo) {}

  place(item: any) {
    return this.repo.save(item);
  }
}
