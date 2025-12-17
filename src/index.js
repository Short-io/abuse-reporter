#!/usr/bin/env node

/**
 * Log to Abuse Reports
 *
 * Reads log stream from stdin, extracts unique IP addresses,
 * looks up abuse contacts, and generates abuse report emails.
 *
 * Usage:
 *   cat /var/log/auth.log | node src/index.js
 *   tail -n 1000 /var/log/nginx/access.log | node src/index.js --sender-email admin@example.com
 */

import { createInterface } from 'readline';
import { buildIPLogMap } from './ip-extractor.js';
import { lookupIPs, groupByAbuseEmail } from './abuse-lookup.js';
import {
  generateAllEmails,
  formatEmailForOutput,
  generateUnknownIPsSummary,
} from './email-generator.js';

/**
 * Parse command line arguments
 * @returns {object} - Parsed options
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    senderEmail: 'abuse@example.com',
    senderName: 'Abuse Reporter',
    senderOrg: 'System Administrator',
    maxLogsPerIP: 50,
    help: false,
    json: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '-h':
      case '--help':
        options.help = true;
        break;
      case '--sender-email':
        options.senderEmail = args[++i];
        break;
      case '--sender-name':
        options.senderName = args[++i];
        break;
      case '--sender-org':
        options.senderOrg = args[++i];
        break;
      case '--max-logs':
        options.maxLogsPerIP = parseInt(args[++i], 10);
        break;
      case '--json':
        options.json = true;
        break;
    }
  }

  return options;
}

/**
 * Print help message
 */
function printHelp() {
  console.log(`
Log to Abuse Reports - Generate abuse reports from log files

USAGE:
  cat /var/log/auth.log | log-to-abuse [OPTIONS]
  tail -f /var/log/nginx/access.log | log-to-abuse [OPTIONS]

OPTIONS:
  -h, --help              Show this help message
  --sender-email EMAIL    Set sender email address (default: abuse@example.com)
  --sender-name NAME      Set sender name (default: Abuse Reporter)
  --sender-org ORG        Set sender organization (default: System Administrator)
  --max-logs N            Max log entries per IP (default: 50)
  --json                  Output in JSON format instead of text

EXAMPLES:
  # Process auth logs
  cat /var/log/auth.log | log-to-abuse --sender-email admin@mycompany.com

  # Process nginx logs with custom sender
  grep "attack" /var/log/nginx/access.log | log-to-abuse \\
    --sender-email security@mycompany.com \\
    --sender-name "Security Team" \\
    --sender-org "MyCompany Security"

  # Output JSON for further processing
  cat logs.txt | log-to-abuse --json > reports.json
`);
}

/**
 * Read all lines from stdin
 * @returns {Promise<string[]>} - Array of lines
 */
async function readStdin() {
  return new Promise((resolve, reject) => {
    const lines = [];

    // Check if stdin is a TTY (interactive terminal)
    if (process.stdin.isTTY) {
      resolve([]);
      return;
    }

    const rl = createInterface({
      input: process.stdin,
      crlfDelay: Infinity,
    });

    rl.on('line', (line) => {
      lines.push(line);
    });

    rl.on('close', () => {
      resolve(lines);
    });

    rl.on('error', reject);
  });
}

/**
 * Main function
 */
async function main() {
  const options = parseArgs();

  if (options.help) {
    printHelp();
    process.exit(0);
  }

  // Read log lines from stdin
  process.stderr.write('Reading log data from stdin...\n');
  const lines = await readStdin();

  if (lines.length === 0) {
    console.error('No input received. Pipe log data to stdin.');
    console.error('Example: cat /var/log/auth.log | log-to-abuse');
    process.exit(1);
  }

  process.stderr.write(`Read ${lines.length} log lines\n`);

  // Extract IPs and build log map
  process.stderr.write('Extracting IP addresses...\n');
  const ipLogMap = buildIPLogMap(lines);
  const uniqueIPs = Array.from(ipLogMap.keys());

  if (uniqueIPs.length === 0) {
    console.error('No public IP addresses found in the logs.');
    process.exit(0);
  }

  process.stderr.write(`Found ${uniqueIPs.length} unique public IP addresses\n`);

  // Look up WHOIS information for each IP
  process.stderr.write('Looking up abuse contacts (this may take a while)...\n');
  const whoisResults = await lookupIPs(uniqueIPs, (ip, current, total) => {
    process.stderr.write(`\r  [${current}/${total}] Looking up ${ip}...`);
  });
  process.stderr.write('\n');

  // Group IPs by abuse email
  const abuseGroups = groupByAbuseEmail(whoisResults);
  process.stderr.write(`Grouped into ${abuseGroups.size} abuse contacts\n`);

  // Generate emails
  const emails = generateAllEmails(abuseGroups, ipLogMap, options);

  // Output results
  if (options.json) {
    // JSON output
    const output = {
      generated: new Date().toISOString(),
      stats: {
        totalLogLines: lines.length,
        uniqueIPs: uniqueIPs.length,
        abuseContacts: emails.length,
        unknownIPs: abuseGroups.get('unknown@unknown')?.length || 0,
      },
      emails,
      unknownIPs: abuseGroups.get('unknown@unknown') || [],
    };
    console.log(JSON.stringify(output, null, 2));
  } else {
    // Text output
    console.log('\n');
    console.log('='.repeat(78));
    console.log('ABUSE REPORT GENERATION COMPLETE');
    console.log('='.repeat(78));
    console.log('');
    console.log(`Total log lines processed: ${lines.length}`);
    console.log(`Unique public IPs found: ${uniqueIPs.length}`);
    console.log(`Abuse reports generated: ${emails.length}`);
    console.log('');

    // Output each email
    for (const email of emails) {
      console.log(formatEmailForOutput(email));
    }

    // Output unknown IPs summary
    const unknownSummary = generateUnknownIPsSummary(abuseGroups);
    if (unknownSummary) {
      console.log(unknownSummary);
    }
  }

  process.stderr.write('Done!\n');
}

main().catch((error) => {
  console.error('Error:', error.message);
  process.exit(1);
});
