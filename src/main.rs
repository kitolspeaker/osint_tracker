//! Asynchronous OSINT tracker: fetches VirusTotal and Shodan IP data concurrently.
//! Loads API keys from .env; no sensitive data is logged.

use clap::Parser;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use std::env;
use std::net::IpAddr;

const VT_IP_REPORT_URL: &str = "https://www.virustotal.com/api/v3/ip_addresses";
const SHODAN_HOST_URL: &str = "https://api.shodan.io/shodan/host";

/// Automated OSINT IP tracker — queries VirusTotal and Shodan APIs concurrently.
#[derive(Parser, Debug)]
#[command(
    name = "osint_tracker",
    about = "Query VirusTotal and Shodan for IP reputation and host data."
)]
struct Args {
    /// Target IP address to look up (IPv4 or IPv6).
    #[arg(required = true, value_name = "IP_ADDRESS")]
    ip: IpAddr,
}

// ---------- VirusTotal ----------

/// VirusTotal `last_analysis_stats` subset (malicious, suspicious, harmless).
#[derive(Debug, Deserialize)]
struct LastAnalysisStats {
    malicious: u32,
    suspicious: u32,
    harmless: u32,
}

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

// ---------- Shodan ----------

/// Shodan host response subset: only ports, org, os (rest ignored).
#[derive(Debug, Deserialize)]
struct ShodanHostResponse {
    #[serde(default)]
    ports: Vec<u16>,
    org: Option<String>,
    os: Option<String>,
}

// ---------- Client & env ----------

/// Builds a reqwest client with timeouts to avoid hanging on bad networks.
fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
}

fn get_vt_api_key() -> Result<String, String> {
    env::var("VT_API_KEY").map_err(|_| {
        "VT_API_KEY is not set. Add it to your .env file or environment.".to_string()
    })
}

fn get_shodan_api_key() -> Result<String, String> {
    env::var("SHODAN_API_KEY").map_err(|_| {
        "SHODAN_API_KEY is not set. Add it to your .env file or environment.".to_string()
    })
}

// ---------- API fetchers ----------

/// Fetches VirusTotal IP report.
async fn fetch_virustotal(
    client: &reqwest::Client,
    ip: IpAddr,
    api_key: &str,
) -> Result<IpReportResponse, String> {
    let url = format!("{}/{}", VT_IP_REPORT_URL.trim_end_matches('/'), ip);
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-apikey"),
        HeaderValue::from_str(api_key).map_err(|_| "Invalid VT API key (non-ASCII)?")?,
    );

    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| format!("VirusTotal request failed: {}", e))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("VirusTotal response body read failed: {}", e))?;

    if !status.is_success() {
        return Err(format!(
            "VirusTotal API error: HTTP {} - {}",
            status,
            body.lines().next().unwrap_or("(no body)")
        ));
    }

    serde_json::from_str(&body).map_err(|e| format!("VirusTotal parse error: {}", e))
}

/// Fetches Shodan host data. Returns Ok(None) on 404 (IP not in Shodan database).
async fn fetch_shodan(
    client: &reqwest::Client,
    ip: IpAddr,
    api_key: &str,
) -> Result<Option<ShodanHostResponse>, String> {
    let url = format!("{}/{}", SHODAN_HOST_URL.trim_end_matches('/'), ip);

    let response = client
        .get(&url)
        .query(&[("key", api_key)])
        .send()
        .await
        .map_err(|e| format!("Shodan request failed: {}", e))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("Shodan response body read failed: {}", e))?;

    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !status.is_success() {
        return Err(format!(
            "Shodan API error: HTTP {} - {}",
            status,
            body.lines().next().unwrap_or("(no body)")
        ));
    }

    let report: ShodanHostResponse =
        serde_json::from_str(&body).map_err(|e| format!("Shodan parse error: {}", e))?;
    Ok(Some(report))
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = run(args.ip).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run(ip: IpAddr) -> Result<(), String> {
    dotenv::dotenv().ok();

    let vt_api_key = get_vt_api_key()?;
    let shodan_api_key = get_shodan_api_key()?;
    let client = build_client().map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let (vt_result, shodan_result) = tokio::join!(
        fetch_virustotal(&client, ip, &vt_api_key),
        fetch_shodan(&client, ip, &shodan_api_key),
    );

    let vt_report = vt_result?;

    println!("=== OSINT Report: IP {} ===\n", ip);

    // ---------- VirusTotal section ----------
    println!("--- VirusTotal ---");
    let attrs = &vt_report.data.attributes;
    let stats = &attrs.last_analysis_stats;
    println!("AS owner: {}", attrs.as_owner.as_deref().unwrap_or("(unknown)"));
    println!("Last analysis stats:");
    println!("  Malicious:  {}", stats.malicious);
    println!("  Suspicious: {}", stats.suspicious);
    println!("  Harmless:   {}", stats.harmless);

    // ---------- Shodan section ----------
    println!("\n--- Shodan ---");
    match shodan_result {
        Ok(Some(host)) => {
            println!("Organization: {}", host.org.as_deref().unwrap_or("(unknown)"));
            println!("OS: {}", host.os.as_deref().unwrap_or("(unknown)"));
            if host.ports.is_empty() {
                println!("Ports: (none)");
            } else {
                println!("Ports: {:?}", host.ports);
            }
        }
        Ok(None) => {
            println!("No Shodan data is available for this IP.");
        }
        Err(e) => {
            println!("Shodan error: {}", e);
        }
    }

    println!("\n==========================================");

    Ok(())
}
