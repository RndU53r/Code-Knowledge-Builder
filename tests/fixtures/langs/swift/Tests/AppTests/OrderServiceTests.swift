import XCTest

final class OrderServiceTests: XCTestCase {
    func testPlace() {
        _ = OrderService(repo: OrderRepo()).place("a")
    }
}
