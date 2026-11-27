import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import 'service.dart';

class OrderController {
  final OrderService _service;
  OrderController(this._service);

  Router get router {
    final r = Router();
    r.post('/orders', create);
    return r;
  }

  Future<Response> create(Request request) async {
    final auth = request.headers['authorization'];
    if (!authenticate(auth)) return Response(401);
    final body = await request.readAsString();
    _service.place(body);
    return Response.ok('ok');
  }
}

bool authenticate(String? token) => token != null;
