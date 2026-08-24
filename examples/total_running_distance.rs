use std::io::Write;

use garmin_connect::{GarminClient, LoginOutcome};

const PAGE_SIZE: usize = 100;
const MAX_PAGES: usize = 20; // safety cap: 2000 activities

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let email = std::env::var("GARMIN_EMAIL").expect("set GARMIN_EMAIL");
    let password = std::env::var("GARMIN_PASSWORD").expect("set GARMIN_PASSWORD");
    let token_path = "./.garmin_tokens.json";

    let mut client = GarminClient::new("garmin.com")?;

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

    let mut total_distance_m = 0.0;
    let mut run_count = 0usize;
    let mut start = 0usize;

    for _ in 0..MAX_PAGES {
        let page = client
            .get(&format!(
                "/activitylist-service/activities/search/activities?start={start}&limit={PAGE_SIZE}"
            ))
            .await?;
        let page = page.as_array().cloned().unwrap_or_default();
        if page.is_empty() {
            break;
        }

        for activity in &page {
            let type_key = activity["activityType"]["typeKey"].as_str().unwrap_or("");
            if type_key.contains("running") {
                total_distance_m += activity["distance"].as_f64().unwrap_or(0.0);
                run_count += 1;
            }
        }

        if page.len() < PAGE_SIZE {
            break;
        }
        start += PAGE_SIZE;
    }

    println!("Running activities: {run_count}");
    println!("Total running distance: {:.2} km", total_distance_m / 1000.0);

    Ok(())
}
