package shop

import scalaj.http.Http

class BaseRepo {
  def save(item: String): String = {
    item
  }
}

class OrderRepo(conn: java.sql.Connection) extends BaseRepo {
  override def save(item: String): String = {
    Http("http://billing/charge").postData(item).asString
    conn.createStatement().executeQuery("SELECT * FROM orders WHERE id = " + item)
    super.save(item)
  }
}
