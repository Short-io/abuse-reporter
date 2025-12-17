/**
 * Abuse contact lookup using WHOIS
 */

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Cache for WHOIS lookups to avoid repeated queries
const whoisCache = new Map();

// Rate limiting: delay between WHOIS queries (ms)
const WHOIS_DELAY = 1000;
let lastWhoisQuery = 0;

/**
 * Extract abuse email from WHOIS output
 * @param {string} whoisOutput - Raw WHOIS output
 * @returns {string|null} - Abuse email or null
 */
function extractAbuseEmail(whoisOutput) {
  const lines = whoisOutput.split('\n');

  // Patterns to look for abuse email (in order of preference)
  const patterns = [
    /abuse.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i,
    /OrgAbuseEmail:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i,
    /RAbuseEmail:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i,
    /abuse-mailbox:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i,
    /% Abuse contact for .* is '([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'/i,
  ];

  for (const line of lines) {
    for (const pattern of patterns) {
      const match = line.match(pattern);
      if (match && match[1]) {
        return match[1].toLowerCase();
      }
    }
  }

  return null;
}

/**
 * Extract organization/network name from WHOIS output
 * @param {string} whoisOutput - Raw WHOIS output
 * @returns {string} - Organization name or 'Unknown'
 */
function extractOrgName(whoisOutput) {
  const patterns = [
    /OrgName:\s*(.+)/i,
    /org-name:\s*(.+)/i,
    /Organization:\s*(.+)/i,
    /netname:\s*(.+)/i,
    /descr:\s*(.+)/i,
  ];

  for (const pattern of patterns) {
    const match = whoisOutput.match(pattern);
    if (match && match[1]) {
      return match[1].trim();
    }
  }

  return 'Unknown';
}

/**
 * Extract network range from WHOIS output
 * @param {string} whoisOutput - Raw WHOIS output
 * @returns {string|null} - Network range or null
 */
function extractNetRange(whoisOutput) {
  const patterns = [
    /NetRange:\s*(.+)/i,
    /inetnum:\s*(.+)/i,
    /CIDR:\s*(.+)/i,
  ];

  for (const pattern of patterns) {
    const match = whoisOutput.match(pattern);
    if (match && match[1]) {
      return match[1].trim();
    }
  }

  return null;
}

/**
 * Extract country from WHOIS output
 * @param {string} whoisOutput - Raw WHOIS output
 * @returns {string|null} - Country code or null
 */
function extractCountry(whoisOutput) {
  const patterns = [
    /Country:\s*([A-Z]{2})/i,
    /country:\s*([A-Z]{2})/i,
  ];

  for (const pattern of patterns) {
    const match = whoisOutput.match(pattern);
    if (match && match[1]) {
      return match[1].toUpperCase();
    }
  }

  return null;
}

/**
 * Rate-limited delay
 */
async function rateLimitDelay() {
  const now = Date.now();
  const elapsed = now - lastWhoisQuery;
  if (elapsed < WHOIS_DELAY) {
    await new Promise(resolve => setTimeout(resolve, WHOIS_DELAY - elapsed));
  }
  lastWhoisQuery = Date.now();
}

/**
 * Perform WHOIS lookup for an IP address
 * @param {string} ip - IP address to lookup
 * @returns {Promise<object>} - WHOIS information
 */
export async function lookupIP(ip) {
  // Check cache first
  if (whoisCache.has(ip)) {
    return whoisCache.get(ip);
  }

  await rateLimitDelay();

  try {
    const { stdout } = await execAsync(`whois ${ip}`, { timeout: 30000 });

    const result = {
      ip,
      abuseEmail: extractAbuseEmail(stdout),
      orgName: extractOrgName(stdout),
      netRange: extractNetRange(stdout),
      country: extractCountry(stdout),
      rawWhois: stdout,
    };

    whoisCache.set(ip, result);
    return result;
  } catch (error) {
    const result = {
      ip,
      abuseEmail: null,
      orgName: 'Unknown',
      netRange: null,
      country: null,
      error: error.message,
    };
    whoisCache.set(ip, result);
    return result;
  }
}

/**
 * Lookup abuse contacts for multiple IPs
 * @param {string[]} ips - Array of IP addresses
 * @param {function} onProgress - Progress callback (ip, index, total)
 * @returns {Promise<Map<string, object>>} - Map of IP -> WHOIS info
 */
export async function lookupIPs(ips, onProgress = null) {
  const results = new Map();
  const total = ips.length;

  for (let i = 0; i < ips.length; i++) {
    const ip = ips[i];
    if (onProgress) {
      onProgress(ip, i + 1, total);
    }
    const info = await lookupIP(ip);
    results.set(ip, info);
  }

  return results;
}

/**
 * Group IPs by their abuse email
 * @param {Map<string, object>} whoisResults - Map of IP -> WHOIS info
 * @returns {Map<string, object[]>} - Map of abuseEmail -> array of WHOIS info
 */
export function groupByAbuseEmail(whoisResults) {
  const groups = new Map();

  for (const [ip, info] of whoisResults) {
    const email = info.abuseEmail || 'unknown@unknown';

    if (!groups.has(email)) {
      groups.set(email, []);
    }
    groups.get(email).push(info);
  }

  return groups;
}
