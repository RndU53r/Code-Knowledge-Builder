import { OrderService } from './order.service';

describe('OrderService', () => {
  it('places', () => {
    expect(new OrderService(null as any).place({})).toBeDefined();
  });
});
