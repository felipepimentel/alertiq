use actix_web::{post, web, App, HttpServer, Responder, middleware::Logger};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;
use dotenv::dotenv;
use std::env;
use colored::*;
use chrono::Local;
use log::info;

const DEFAULT_PORT: u16 = 5000;

#[derive(Serialize)]
struct Claims {
    iat: usize,
    exp: usize,
    iss: String,
}

/// Generates a JWT for GitHub App authentication
fn generate_jwt() -> Result<String, Box<dyn std::error::Error>> {
    let app_id = env::var("GITHUB_APP_ID")
        .expect("GITHUB_APP_ID must be set");
    let private_key_path = env::var("GITHUB_PRIVATE_KEY_PATH")
        .expect("GITHUB_PRIVATE_KEY_PATH must be set");

    let private_key = fs::read(private_key_path)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() as usize;

    let claims = Claims {
        iat: now,
        exp: now + 600, // Token valid for 10 minutes
        iss: app_id,
    };

    Ok(encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(&private_key)?
    )?)
}

/// Log webhook details
fn log_webhook_details(payload: &serde_json::Value) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!("\n{}", "=".repeat(50).yellow());
    println!("{} {}", timestamp.blue(), "Webhook Received".green());
    
    // Log event type if present
    if let Some(event_type) = payload.get("action") {
        println!("Event Type: {}", event_type.to_string().cyan());
    }

    // Log repository details
    if let Some(repo) = payload.get("repository") {
        if let Some(repo_name) = repo.get("full_name") {
            println!("Repository: {}", repo_name.to_string().cyan());
        }
    }

    // Log the complete payload for debugging
    println!("\nComplete Payload:");
    println!("{}", serde_json::to_string_pretty(payload).unwrap().white());
    println!("{}\n", "=".repeat(50).yellow());
}

/// Webhook event handler
#[post("/webhook")]
async fn webhook_handler(payload: web::Json<serde_json::Value>) -> impl Responder {
    log_webhook_details(&payload);
    web::Json(serde_json::json!({"status": "success"}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let port = env::var("PORT")
        .unwrap_or(DEFAULT_PORT.to_string())
        .parse::<u16>()
        .unwrap_or(DEFAULT_PORT);

    // Generate and display JWT token
    match generate_jwt() {
        Ok(token) => info!("JWT Token generated successfully"),
        Err(e) => eprintln!("Failed to generate JWT token: {}", e),
    }

    println!("{}", "\nGitHub Webhook Server".green().bold());
    println!("{} {}", "Server starting on port:".yellow(), port.to_string().cyan());
    println!("{} {}\n", "Local URL:".yellow(), format!("http://localhost:{}", port).cyan());

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(webhook_handler)
    })
    .bind(("0.0.0.0", port))?
    .workers(2)
    .run()
    .await
}
