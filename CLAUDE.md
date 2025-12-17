# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Node.js CLI tool that processes log streams, extracts unique public IP addresses, performs WHOIS lookups to find abuse contacts, and generates formatted abuse report emails. Emails are saved to organized directories by provider.

## Commands

```bash
# Install dependencies
yarn install

# Run the tool (pipe logs to stdin)
cat /var/log/auth.log | node src/index.js

# Run tests
node --test src/**/*.test.js
```

## Architecture

The tool uses a pipeline architecture with three main modules:

1. **ip-extractor.js** - Extracts IPv4/IPv6 addresses from log lines, filters out private/local IPs, builds a map of IP → log entries
2. **abuse-lookup.js** - Performs WHOIS lookups via the system `whois` command, extracts abuse email/org/country from output, rate-limited to 1 second between queries, caches results
3. **email-generator.js** - Generates formatted abuse report emails grouped by abuse contact, outputs to text or JSON format

Flow: stdin → extract IPs → WHOIS lookup → group by abuse email → generate emails → save to `emails/<provider>/` directories

## Key Technical Details

- ES Modules (`"type": "module"`)
- Requires Node.js 18+
- Requires system `whois` command installed
- Progress output goes to stderr, results go to stdout
- IPs without discoverable abuse contacts are grouped under `unknown@unknown` and listed separately
