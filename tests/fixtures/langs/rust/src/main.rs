mod handlers;
mod service;
mod repo;

use axum::{routing::post, Router};

fn app() -> Router {
    Router::new().route("/orders", post(handlers::create)).layer(RequireAuthorizationLayer::bearer("token"))
}
