# OSINT Tracker

Automated **OSINT IP Tracker** that queries **VirusTotal** and **Shodan** **concurrently** for a given IP address. It retrieves VirusTotal reputation (last analysis stats, AS owner) and Shodan host data (open ports, organization, OS) in a single run.

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
   ```bash
   # Windows (PowerShell)
   @"
   VT_API_KEY=your_virustotal_key_here
   SHODAN_API_KEY=your_shodan_key_here
   "@ | Set-Content -Path .env -Encoding utf8

   # Linux / macOS
   echo 'VT_API_KEY=your_virustotal_key_here
   SHODAN_API_KEY=your_shodan_key_here' > .env
   ```

3. **Replace** `your_virustotal_key_here` and `your_shodan_key_here` with your actual API keys. Do not commit `.env` to version control (it is listed in `.gitignore`).

## Usage

**Run with a target IP (required):**
```bash
cargo run -- 8.8.8.8
```

**Example combined report output:**
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

If the IP is not in Shodan’s database, the Shodan section will show:
```
--- Shodan ---
No Shodan data is available for this IP.
```

**Additional examples:**
```bash
cargo run -- 1.1.1.1
cargo run -- 192.168.1.1
```

**Show help and usage:**
```bash
cargo run -- --help
```

Or, after building the binary:
```bash
cargo build --release
./target/release/osint_tracker --help
./target/release/osint_tracker 8.8.8.8
```
