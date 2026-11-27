import 'package:sqflite/sqflite.dart';

abstract class BaseRepo {
  String save(String item) => item;
}

class OrderRepo extends BaseRepo {
  final Database? db;
  OrderRepo(this.db);

  @override
  String save(String item) {
    db?.rawQuery("SELECT * FROM orders WHERE item = '$item'");
    return item;
  }
}
