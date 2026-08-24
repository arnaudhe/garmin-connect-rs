use std::io::Write;

use garmin_connect::{GarminClient, LoginOutcome};

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

    let activities = client
        .get("/activitylist-service/activities/search/activities?start=0&limit=10")
        .await?;

    let activities = activities
        .as_array()
        .cloned()
        .unwrap_or_default();

    if activities.is_empty() {
        println!("No activities found.");
        return Ok(());
    }

    println!("Last {} activities:\n", activities.len());

    for activity in &activities {
        let name = activity["activityName"].as_str().unwrap_or("(unnamed)");
        let activity_type = activity["activityType"]["typeKey"]
            .as_str()
            .unwrap_or("unknown");
        let start = activity["startTimeLocal"].as_str().unwrap_or("?");
        let distance_km = activity["distance"].as_f64().unwrap_or(0.0) / 1000.0;
        let duration_s = activity["duration"].as_f64().unwrap_or(0.0);
        let calories = activity["calories"].as_f64().unwrap_or(0.0);
        let avg_hr = activity["averageHR"].as_f64();

        println!("- {name} [{activity_type}]");
        println!("    date:     {start}");
        println!("    distance: {distance_km:.2} km");
        println!("    duration: {}", format_duration(duration_s));
        println!("    calories: {calories:.0}");
        if let Some(hr) = avg_hr {
            println!("    avg HR:   {hr:.0} bpm");
        }
        println!();
    }

    Ok(())
}

fn format_duration(total_seconds: f64) -> String {
    let total_seconds = total_seconds.round() as u64;
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    if hours > 0 {
        format!("{hours}h{minutes:02}m{seconds:02}s")
    } else {
        format!("{minutes}m{seconds:02}s")
    }
}
