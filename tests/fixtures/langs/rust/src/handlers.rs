use crate::service::OrderService;

pub struct AppState {
    pub service: OrderService,
}

pub async fn create(state: State<AppState>, body: Json<String>) -> String {
    state.service.place(body.0)
}
