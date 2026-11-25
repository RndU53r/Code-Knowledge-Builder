import Foundation

class BaseRepo {
    func save(_ item: String) -> String {
        return item
    }
}

class OrderRepo: BaseRepo {
    override func save(_ item: String) -> String {
        URLSession.shared.dataTask(with: URL(string: "http://billing/charge")!)
        sqlite3_exec(db, "SELECT * FROM orders WHERE id = " + item)
        return super.save(item)
    }
}
