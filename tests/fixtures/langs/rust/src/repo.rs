pub trait Repo {
    fn save(&self, item: String) -> String;
}

pub struct OrderRepo {
    db: Db,
}

impl Repo for OrderRepo {
    fn save(&self, item: String) -> String {
        reqwest::get("http://billing/charge");
        sqlx::query(&format!("SELECT * FROM orders WHERE id = {}", item));
        item
    }
}
