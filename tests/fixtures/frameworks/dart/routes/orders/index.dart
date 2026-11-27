import 'package:dart_frog/dart_frog.dart';
import 'package:go_router/go_router.dart';
import 'package:flutter/services.dart';

Future<Response> onRequest(RequestContext context) async {
  return Response(body: 'ok');
}

final router = GoRouter(routes: [
  GoRoute(path: '/orders', builder: (context, state) => OrdersScreen()),
]);

final routes = {'/settings': (context) => SettingsScreen()};

class Shop {
  @Route.post('/shelf/orders')
  Future<Response> create(Request request) async => Response.ok('ok');
}

class OrdersEndpoint extends Endpoint {
  Future<String> create(Session session, String item) async => item;
}

const channel = MethodChannel('com.acme/orders');
Future<void> native() async {
  await channel.invokeMethod('create');
}
