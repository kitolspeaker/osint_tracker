//! Asynchronous OSINT tracker: fetches VirusTotal and Shodan IP data concurrently.
//! Supports single-IP or bulk scan from file; respects VT free-tier rate limits.

use clap::Parser;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::PathBuf;

const VT_IP_REPORT_URL: &str = "https://www.virustotal.com/api/v3/ip_addresses";
const SHODAN_HOST_URL: &str = "https://api.shodan.io/shodan/host";
/// VirusTotal free tier: 4 requests/minute — delay between bulk IPs to avoid 429.
const BULK_RATE_LIMIT_SECS: u64 = 15;

/// Automated OSINT IP tracker — VirusTotal and Shodan (single IP or bulk from file).
#[derive(Parser, Debug)]
#[command(
    name = "osint_tracker",
    about = "Query VirusTotal and Shodan for IP reputation and host data."
)]
struct Args {
    #[command(flatten)]
    input: InputSource,
}

/// Exactly one of --ip or --file must be provided.
#[derive(clap::Args, Debug)]
#[group(required = true, multiple = false)]
struct InputSource {
    /// Target IP address (single-IP mode).
    #[arg(short, long, value_name = "IP_ADDRESS")]
    ip: Option<IpAddr>,

    /// File with one IP per line (bulk mode). Empty lines and invalid IPs are ignored.
    #[arg(short, long, value_name = "FILE")]
    file: Option<PathBuf>,
}

// ---------- VirusTotal ----------

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

#[derive(Debug, Deserialize)]
struct ShodanHostResponse {
    #[serde(default)]
    ports: Vec<u16>,
    org: Option<String>,
    os: Option<String>,
}

// ---------- Client & env ----------

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

// ---------- File input ----------

/// Reads IPs from file (one per line). Skips empty lines and invalid IPs.
fn read_ips_from_file(path: &PathBuf) -> Result<Vec<IpAddr>, String> {
    let f = File::open(path).map_err(|e| format!("Cannot open file {:?}: {}", path, e))?;
    let reader = BufReader::new(f);
    let ips: Vec<IpAddr> = reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let s = line.trim();
            if s.is_empty() {
                return None;
            }
            s.parse::<IpAddr>().ok()
        })
        .collect();
    if ips.is_empty() {
        return Err(format!(
            "No valid IP addresses found in {:?} (empty lines and invalid formats are ignored).",
            path
        ));
    }
    Ok(ips)
}

// ---------- API fetchers ----------

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

// ---------- Output ----------

/// Prints one OSINT report (VirusTotal + Shodan) for a single IP.
fn print_report(
    ip: IpAddr,
    vt_result: &Result<IpReportResponse, String>,
    shodan_result: &Result<Option<ShodanHostResponse>, String>,
) {
    println!("=== OSINT Report: IP {} ===\n", ip);

    match vt_result {
        Ok(vt_report) => {
            println!("--- VirusTotal ---");
            let attrs = &vt_report.data.attributes;
            let stats = &attrs.last_analysis_stats;
            println!(
                "AS owner: {}",
                attrs.as_owner.as_deref().unwrap_or("(unknown)")
            );
            println!("Last analysis stats:");
            println!("  Malicious:  {}", stats.malicious);
            println!("  Suspicious: {}", stats.suspicious);
            println!("  Harmless:   {}", stats.harmless);
        }
        Err(e) => {
            println!("--- VirusTotal ---");
            println!("Error: {}", e);
        }
    }

    println!("\n--- Shodan ---");
    match shodan_result {
        Ok(Some(host)) => {
            println!(
                "Organization: {}",
                host.org.as_deref().unwrap_or("(unknown)")
            );
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
}

// ---------- Main & run ----------

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let ips: Vec<IpAddr> = match (&args.input.ip, &args.input.file) {
        (Some(ip), None) => vec![*ip],
        (None, Some(path)) => match read_ips_from_file(path) {
            Ok(list) => list,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        (Some(_), Some(_)) => unreachable!("clap group ensures mutual exclusivity"),
        (None, None) => unreachable!("clap group requires one"),
    };

    let bulk = ips.len() > 1;
    if let Err(e) = run(ips, bulk).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run(ips: Vec<IpAddr>, bulk_mode: bool) -> Result<(), String> {
    dotenv::dotenv().ok();

    let vt_api_key = get_vt_api_key()?;
    let shodan_api_key = get_shodan_api_key()?;
    let client = build_client().map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let total = ips.len();

    for (i, &ip) in ips.iter().enumerate() {
        if bulk_mode {
            println!("=========================");
            println!("[{} / {}] Processing {}...", i + 1, total, ip);
        }

        let (vt_result, shodan_result) = tokio::join!(
            fetch_virustotal(&client, ip, &vt_api_key),
            fetch_shodan(&client, ip, &shodan_api_key),
        );

        if !bulk_mode {
            vt_result.as_ref().map_err(|e| e.clone())?;
        }

        print_report(ip, &vt_result, &shodan_result);

        // VT free tier: 4 req/min — mandatory delay between IPs in bulk to avoid 429.
        if bulk_mode && i + 1 < total {
            println!(
                "Waiting {} seconds (rate limit) before next IP...",
                BULK_RATE_LIMIT_SECS
            );
            tokio::time::sleep(std::time::Duration::from_secs(BULK_RATE_LIMIT_SECS)).await;
        }
    }

    Ok(())
}
