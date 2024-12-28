use actix_web::{get, post, web, App, HttpServer, Responder, middleware::Logger};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;
use dotenv::dotenv;
use std::env;
use colored::*;
use chrono::Local;
use log::info;
use notify_rust::Notification;

const DEFAULT_PORT: u16 = 5000;

#[derive(Serialize)]
struct Claims {
    iat: usize,
    exp: usize,
    iss: String,
}

/// Send desktop notification
fn send_notification(title: &str, body: &str, url: Option<&str>) {
    let mut notification_base = Notification::new();
    let mut notification = notification_base
        .summary(title)
        .body(body)
        .icon("github")
        .timeout(notify_rust::Timeout::Milliseconds(5000)); // 5 seconds

    if let Some(url) = url {
        let body_with_url = format!("{}\n\nClick to open: {}", body, url);
        notification = notification.body(&body_with_url);
    }

    if let Err(e) = notification.show() {
        eprintln!("Failed to show notification: {}", e);
    }
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

/// Log webhook details and send notifications
fn handle_workflow_event(payload: &serde_json::Value) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!("\n{}", "=".repeat(50).yellow());
    println!("{} {}", timestamp.blue(), "Workflow Event Received".green());
    
    if let Some(workflow_run) = payload.get("workflow_run") {
        let repo_name = payload["repository"]["full_name"].as_str().unwrap_or("unknown");
        let workflow_name = workflow_run["name"].as_str().unwrap_or("unknown");
        let status = workflow_run["status"].as_str().unwrap_or("unknown");
        let conclusion = workflow_run["conclusion"].as_str().unwrap_or("unknown");
        let html_url = workflow_run["html_url"].as_str();
        let commit_message = workflow_run["head_commit"]["message"].as_str().unwrap_or("No commit message");

        println!("Repository: {}", repo_name.cyan());
        println!("Workflow: {}", workflow_name.cyan());
        println!("Status: {}", status.yellow());
        println!("Conclusion: {}", conclusion.yellow());
        println!("Commit: {}", commit_message.white());
        
        if let Some(url) = html_url {
            println!("URL: {}", url.blue().underline());
            
            let icon = match conclusion {
                "success" => "✅",
                "failure" => "❌",
                "cancelled" => "⚪",
                "skipped" => "⏭️",
                _ => "🔄"
            };
            
            let title = format!("GitHub Workflow {}", icon);
            
            let body = format!("{}\n{}\nStatus: {}\nRepo: {}",
                workflow_name,
                commit_message.lines().next().unwrap_or(""),
                conclusion.to_uppercase(),
                repo_name);
            
            send_notification(&title, &body, Some(url));
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
    handle_workflow_event(&payload);
    web::Json(serde_json::json!({"status": "success"}))
}

/// Health check endpoint
#[get("/")]
async fn health_check() -> impl Responder {
    web::Json(serde_json::json!({
        "status": "online",
        "message": "GitHub Webhook Server is running",
        "version": env!("CARGO_PKG_VERSION")
    }))
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
        Ok(_token) => info!("JWT Token generated successfully"),
        Err(e) => eprintln!("Failed to generate JWT token: {}", e),
    }

    println!("{}", "\nGitHub Webhook Server".green().bold());
    println!("{} {}", "Server starting on port:".yellow(), port.to_string().cyan());
    println!("{} {}\n", "Local URL:".yellow(), format!("http://localhost:{}", port).cyan());

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(health_check)
            .service(webhook_handler)
    })
    .bind(("0.0.0.0", port))?
    .workers(2)
    .run()
    .await
}
