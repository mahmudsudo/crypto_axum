use axum::Json;

pub async fn protected_handler() -> Json<&'static str> {
    Json("Access granted!")
}
