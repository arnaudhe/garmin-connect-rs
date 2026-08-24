use std::io::Write;

use garmin_connect::{GarminClient, LoginOutcome};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let email = std::env::var("GARMIN_EMAIL").expect("set GARMIN_EMAIL");
    let password = std::env::var("GARMIN_PASSWORD").expect("set GARMIN_PASSWORD");
    let token_path = "./.garmin_tokens.json";

    let mut client = GarminClient::new("garmin.com")?;

    // Try resuming a previous session first.
    if client.load(token_path).is_ok() {
        println!("Resumed session from {token_path}");
    } else {
        match client.login(&email, &password).await? {
            LoginOutcome::Success => println!("Logged in"),
            LoginOutcome::NeedsMfa(ctx) => {
                print!("Enter MFA code: ");
                std::io::stdout().flush()?;
                let mut code = String::new();
                std::io::stdin().read_line(&mut code)?;
                client.resume_login(ctx, code.trim()).await?;
                println!("Logged in after MFA");
            }
        }
        client.dump(token_path)?;
    }

    let profile = client.get("/userprofile-service/socialProfile").await?;
    println!("{}", serde_json::to_string_pretty(&profile)?);

    Ok(())
}
