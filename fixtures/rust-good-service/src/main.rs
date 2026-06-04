use std::process::Command;
use std::time::Duration;

use actix_cors::Cors;

fn main() {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("client builder should accept timeout");
    let user_id = std::env::args().nth(1).unwrap_or_else(|| "0".to_string());
    let query = sqlx::query("SELECT id, email FROM users WHERE id = $1").bind(&user_id);
    let status = Command::new("/usr/bin/id").arg(&user_id).status();
    let cors = Cors::default().allowed_origin("https://admin.example.com");
    drop((client, query, status, cors));
}
