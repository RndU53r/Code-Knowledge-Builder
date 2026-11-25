import Vapor

struct OrderController {
    let service: OrderService

    func create(req: Request) async throws -> String {
        return service.place(try req.content.decode(String.self))
    }
}
