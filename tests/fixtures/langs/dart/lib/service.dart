import 'package:http/http.dart' as http;
import 'repo.dart';

class OrderService {
  final OrderRepo _repo;
  OrderService(this._repo);

  Future<String> place(String item) async {
    await http.get(Uri.parse('http://billing/charge'));
    return _repo.save(item);
  }
}
