import 'dart:io';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shop/controller.dart';
import 'package:shop/service.dart';
import 'package:shop/repo.dart';

Future<void> main(List<String> args) async {
  final repo = OrderRepo(null);
  final controller = OrderController(OrderService(repo));
  await shelf_io.serve(controller.router, InternetAddress.anyIPv4, 8080);
}
