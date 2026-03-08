//! Asynchronous OSINT tracker: fetches VirusTotal IP report and prints selected attributes.
//! Loads API key from .env; no sensitive data is logged.

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use std::env;

const VT_IP_REPORT_URL: &str = "https://www.virustotal.com/api/v3/ip_addresses";
const TEST_IP: &str = "8.8.8.8";

/// VirusTotal `last_analysis_stats` subset (malicious, suspicious, harmless).
/// Other fields (e.g. undetected, timeout) are ignored via serde.
#[derive(Debug, Deserialize)]
struct LastAnalysisStats {
    malicious: u32,
    suspicious: u32,
    harmless: u32,
}

/// IP report attributes we care about; rest of response is ignored.
#[derive(Debug, Deserialize)]
struct IpAttributes {
    #[serde(rename = "last_analysis_stats")]
    last_analysis_stats: LastAnalysisStats,
    #[serde(rename = "as_owner")]
    as_owner: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpReportData {
    attributes: IpAttributes,
}

#[derive(Debug, Deserialize)]
struct IpReportResponse {
    data: IpReportData,
}

/// Builds a reqwest client with timeouts to avoid hanging on bad networks.
fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
}

/// Fetches VT API key from environment; fails if missing.
fn get_api_key() -> Result<String, String> {
    env::var("VT_API_KEY").map_err(|_| {
        "VT_API_KEY is not set. Add it to your .env file or environment.".to_string()
    })
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    // Load .env so VT_API_KEY is available (secure: not logged).
    dotenv::dotenv().ok();

    let api_key = get_api_key()?;
    let client = build_client().map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let url = format!("{}/{}", VT_IP_REPORT_URL.trim_end_matches('/'), TEST_IP);
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-apikey"),
        HeaderValue::from_str(api_key.as_str())
            .map_err(|_| "Invalid API key (non-ASCII)?")?,
    );

    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| format!("Network request failed: {}", e))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    if !status.is_success() {
        return Err(format!(
            "VirusTotal API error: HTTP {} - {}",
            status,
            body.lines().next().unwrap_or("(no body)")
        ));
    }

    let report: IpReportResponse = serde_json::from_str(&body).map_err(|e| {
        format!("Failed to parse VirusTotal response: {}", e)
    })?;

    let attrs = &report.data.attributes;
    let stats = &attrs.last_analysis_stats;

    println!("=== OSINT Report: IP {} ===\n", TEST_IP);
    println!("AS owner: {}", attrs.as_owner.as_deref().unwrap_or("(unknown)"));
    println!("\nLast analysis stats:");
    println!("  Malicious:  {}", stats.malicious);
    println!("  Suspicious: {}", stats.suspicious);
    println!("  Harmless:   {}", stats.harmless);
    println!("\n==========================================");

    Ok(())
}
