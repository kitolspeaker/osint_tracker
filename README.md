# OSINT Tracker

Automated **OSINT IP Tracker** that queries **VirusTotal** and **Shodan** concurrently for one or many IP addresses. It supports **single-IP lookup** and **bulk scan from a text file**, retrieving VirusTotal reputation (last analysis stats, AS owner) and Shodan host data (open ports, organization, OS).

## Key Features & Tech Stack

- **High-Performance Concurrency** — Built with `tokio` to perform asynchronous API requests concurrently, minimizing wait times for multi-source intelligence gathering.
- **Defensive Programming** — Utilizes Rust’s strict type system (`std::net::IpAddr`) to validate and sanitize IP inputs before any network activity.
- **Production-Grade CLI** — Powered by `clap` (v4) with mutually exclusive arguments and built-in help menus.
- **Resilient Error Handling** — Gracefully handles API failures and network timeouts without halting bulk operations.

## Security & Best Practices

- **Environment Secrecy** — Uses `dotenv` to prevent sensitive API keys from being hardcoded or accidentally committed to source control.
- **Input Sanitization** — Automatically ignores malformed lines and invalid IP formats to prevent processing errors during bulk scans.
- **API Integrity** — Implements 15-second back-off timers to comply with provider terms of service and avoid IP blacklisting.

## Prerequisites

- **Rust** — Install from [rustup.rs](https://rustup.rs/) (stable toolchain).
- **VirusTotal API key** — Sign up at [VirusTotal](https://www.virustotal.com/) and obtain an API key from your account settings.
- **Shodan API key** — Sign up at [Shodan](https://www.shodan.io/) and get an API key from your account.

## Setup

1. **Clone or navigate to the project:**
   ```bash
   cd osint_tracker
   ```

2. **Create a `.env` file** in the project root (same directory as `Cargo.toml`) with **both** API keys:

   | Variable         | Description              |
   |------------------|--------------------------|
   | `VT_API_KEY`     | Your VirusTotal API key  |
   | `SHODAN_API_KEY` | Your Shodan API key      |

   ```bash
   # Windows (PowerShell)
   @"
   VT_API_KEY=your_virustotal_key_here
   SHODAN_API_KEY=your_shodan_key_here
   "@ | Set-Content -Path .env

   # Linux / macOS
   echo 'VT_API_KEY=your_virustotal_key_here
   SHODAN_API_KEY=your_shodan_key_here' > .env
   ```

3. **Replace** the placeholder values with your actual API keys. Do not commit `.env` to version control (it is listed in `.gitignore`).

## Usage

You must provide **either** a single IP **or** a file path—the two options are mutually exclusive.

| Argument            | Short | Description                                      |
|---------------------|-------|--------------------------------------------------|
| `--ip <IP_ADDRESS>` | `-i`  | Single-IP lookup (one target).                   |
| `--file <FILE_PATH>`| `-f`  | Bulk lookup: text file with one IP per line.    |

### Single-IP mode

```bash
cargo run -- --ip 8.8.8.8
# or
cargo run -- -i 1.1.1.1
```

### Bulk mode

```bash
cargo run -- --file ips.txt
# or
cargo run -- -f ips.txt
```

**Bulk file format:** One IP address per line (IPv4 or IPv6). Empty lines and lines that are not valid IPs are ignored.

**Bulk mode behavior:**

- Uses a streaming file reader (BufReader) to handle large input files efficiently without loading the entire list into memory. VirusTotal and Shodan are queried **concurrently per IP**.
- If one IP fails (e.g. API error, network issue), the error is **logged in the report** for that IP and the tool **continues to the next IP** after the rate-limit delay. It does not abort the entire run.
- Progress is shown as `[1/5] Processing 8.8.8.8...` so you can see which IP is being processed.

### Rate limiting (bulk mode)

To respect **VirusTotal’s free-tier limit of 4 requests per minute**, the tool enforces a **15-second delay** between processing each IP when running in bulk mode. This avoids HTTP 429 (Too Many Requests) and aligns with typical API usage policies. The delay is applied only between IPs; there is no delay after the last IP.

### Help

```bash
cargo run -- --help
```

### Example report output

```
=== OSINT Report: IP 8.8.8.8 ===

--- VirusTotal ---
AS owner: Google LLC
Last analysis stats:
  Malicious:  0
  Suspicious: 0
  Harmless:   90

--- Shodan ---
Organization: Google LLC
OS: (unknown)
Ports: [443, 53]

==========================================
```

If the IP is not in Shodan’s database:

```
--- Shodan ---
No Shodan data is available for this IP.
```

### Release build

```bash
cargo build --release
./target/release/osint_tracker --help
./target/release/osint_tracker --ip 8.8.8.8
./target/release/osint_tracker --file ips.txt
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
