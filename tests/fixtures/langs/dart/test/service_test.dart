import 'package:test/test.dart';
import 'package:shop/service.dart';
import 'package:shop/repo.dart';

void main() {
  test('places', () async {
    final svc = OrderService(OrderRepo(null));
    expect(await svc.place('book'), 'book');
  });
}
