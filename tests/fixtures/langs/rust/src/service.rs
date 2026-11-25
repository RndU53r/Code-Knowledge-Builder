use crate::repo::OrderRepo;

pub struct OrderService {
    repo: OrderRepo,
}

impl OrderService {
    pub fn place(&self, item: String) -> String {
        self.repo.save(item)
    }
}
