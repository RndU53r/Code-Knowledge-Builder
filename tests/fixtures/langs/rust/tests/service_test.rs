#[test]
fn places() {
    let s = shop::OrderService::new();
    s.place("a".to_string());
}
