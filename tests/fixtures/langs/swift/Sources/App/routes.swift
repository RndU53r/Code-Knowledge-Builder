import Vapor

func routes(_ app: Application) throws {
    let protected = app.grouped(AuthMiddleware())
    protected.post("orders", use: OrderController(service: OrderService(repo: OrderRepo())).create)
}
