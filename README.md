# Log to Abuse Reports

A Node.js CLI tool that processes log streams, extracts unique IP addresses, looks up abuse contacts via WHOIS, and generates formatted abuse report emails.

## Requirements

- Node.js >= 18.0.0
- `whois` command-line tool installed on your system

## Installation

```bash
# Install globally via npm
npm install -g @short.io/abuse-reporter

# Or install locally in a project
npm install @short.io/abuse-reporter
```

### From source

```bash
git clone https://github.com/short-io/abuse-reporter.git
cd abuse-reporter
yarn install
npm link
```

## Usage

Pipe log data to stdin:

```bash
# Basic usage
cat /var/log/auth.log | log-to-abuse

# With custom sender information
cat /var/log/nginx/access.log | log-to-abuse \
  --sender-email security@mycompany.com \
  --sender-name "Security Team" \
  --sender-org "MyCompany Inc."

# Output as JSON for further processing
grep "Failed password" /var/log/auth.log | log-to-abuse --json > reports.json

# Process live logs (press Ctrl+C when done)
tail -f /var/log/syslog | log-to-abuse
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-h, --help` | Show help message | - |
| `--sender-email EMAIL` | Sender email address | abuse@example.com |
| `--sender-name NAME` | Sender name | Abuse Reporter |
| `--sender-org ORG` | Sender organization | System Administrator |
| `--max-logs N` | Maximum log entries per IP | 50 |
| `--json` | Output in JSON format | false |

## How It Works

1. **Read logs from stdin** - The tool reads all log lines from standard input
2. **Extract IPs** - Scans each line for IPv4 and IPv6 addresses
3. **Filter private IPs** - Excludes private/local addresses (10.x, 192.168.x, etc.)
4. **WHOIS lookup** - Queries WHOIS for each unique IP to find abuse contacts
5. **Group by provider** - Groups IPs by their abuse email address
6. **Generate reports** - Creates formatted abuse report emails with relevant log excerpts

## Output Format

### Text Output (default)

Generates human-readable abuse report emails:

```
==============================================================================
ABUSE REPORT EMAIL
==============================================================================

To: abuse@provider.com
From: Security Team <security@mycompany.com>
Subject: Abuse Report: Malicious activity from 203.0.113.45
...
```

### JSON Output (--json)

Generates structured JSON for programmatic processing:

```json
{
  "generated": "2024-01-15T10:30:00.000Z",
  "stats": {
    "totalLogLines": 1500,
    "uniqueIPs": 42,
    "abuseContacts": 15,
    "unknownIPs": 3
  },
  "emails": [...],
  "unknownIPs": [...]
}
```

## Example Log Formats Supported

The tool extracts IPs from any text format:

- Apache/Nginx access logs
- SSH auth logs
- Syslog
- Application logs
- Any text containing IP addresses

## Notes

- WHOIS lookups are rate-limited (1 second between queries) to avoid being blocked
- Results are cached during a single run to avoid duplicate queries
- Private/local IP addresses are automatically excluded
- IPs without discoverable abuse contacts are listed separately
