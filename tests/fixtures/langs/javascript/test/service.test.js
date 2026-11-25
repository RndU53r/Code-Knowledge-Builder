const { OrderService } = require('../src/service');

test('place', () => {
  expect(new OrderService().place({ id: 1 })).toBeTruthy();
});
