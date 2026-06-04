use std::process::Command;

use actix_cors::Cors;

fn main() {
    let _client = reqwest::Client::new();
    let user_id = std::env::args().nth(1).unwrap_or_default();
    let _query = sqlx::query(&format!("SELECT * FROM users WHERE id = {}", user_id));
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("useradd {}", user_id))
        .status();
    let _cors = Cors::permissive();
}
