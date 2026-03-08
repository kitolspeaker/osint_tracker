# OSINT Tracker

Automated **OSINT IP Tracker** that queries the [VirusTotal API](https://www.virustotal.com/api/documentation/) to retrieve IP reputation and attributes. The tool fetches last analysis stats (malicious, suspicious, harmless) and AS owner for a given IP address.

## Prerequisites

- **Rust** — Install from [rustup.rs](https://rustup.rs/) (stable toolchain).
- **VirusTotal API key** — Sign up at [VirusTotal](https://www.virustotal.com/) and obtain an API key from your account settings.

## Setup

1. **Clone or navigate to the project:**
   ```bash
   cd osint_tracker
   ```

2. **Create a `.env` file** in the project root (same directory as `Cargo.toml`):
   ```bash
   # Windows (PowerShell)
   New-Item -Path .env -ItemType File -Force
   Set-Content -Path .env -Value "VT_API_KEY=your_api_key_here"

   # Linux / macOS
   echo 'VT_API_KEY=your_api_key_here' > .env
   ```

3. **Replace `your_api_key_here`** with your actual VirusTotal API key. Do not commit `.env` to version control (it is listed in `.gitignore`).

## Usage

**Run with a target IP (required):**
```bash
cargo run -- 8.8.8.8
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
