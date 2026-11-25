struct OrderService {
    let repo: OrderRepo

    func place(_ item: String) -> String {
        return repo.save(item)
    }
}
