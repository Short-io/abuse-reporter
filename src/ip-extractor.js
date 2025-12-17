/**
 * IP address extraction utilities
 */

// IPv4 regex pattern
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

// IPv6 regex pattern (simplified, covers most common formats)
const IPV6_REGEX = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|\b::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

/**
 * Extract all IP addresses from a line of text
 * @param {string} line - Log line to parse
 * @returns {string[]} - Array of IP addresses found
 */
export function extractIPs(line) {
  const ipv4Matches = line.match(IPV4_REGEX) || [];
  const ipv6Matches = line.match(IPV6_REGEX) || [];
  return [...ipv4Matches, ...ipv6Matches];
}

/**
 * Check if an IP is private/local (should be excluded from abuse reports)
 * @param {string} ip - IP address to check
 * @returns {boolean} - True if IP is private/local
 */
export function isPrivateIP(ip) {
  // IPv4 private ranges
  const privateRanges = [
    /^10\./,                          // 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
    /^192\.168\./,                    // 192.168.0.0/16
    /^127\./,                         // 127.0.0.0/8 (loopback)
    /^169\.254\./,                    // 169.254.0.0/16 (link-local)
    /^0\./,                           // 0.0.0.0/8
    /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./, // 100.64.0.0/10 (CGNAT)
  ];

  // IPv6 private/local patterns
  const ipv6Private = [
    /^::1$/i,                         // Loopback
    /^fe80:/i,                        // Link-local
    /^fc00:/i,                        // Unique local
    /^fd[0-9a-f]{2}:/i,              // Unique local
  ];

  for (const range of privateRanges) {
    if (range.test(ip)) return true;
  }

  for (const pattern of ipv6Private) {
    if (pattern.test(ip)) return true;
  }

  return false;
}

/**
 * Process log lines and build a map of IPs to their log entries
 * @param {string[]} lines - Array of log lines
 * @returns {Map<string, string[]>} - Map of IP -> array of log lines
 */
export function buildIPLogMap(lines) {
  const ipLogMap = new Map();

  for (const line of lines) {
    const ips = extractIPs(line);

    for (const ip of ips) {
      if (isPrivateIP(ip)) continue;

      if (!ipLogMap.has(ip)) {
        ipLogMap.set(ip, []);
      }
      ipLogMap.get(ip).push(line);
    }
  }

  return ipLogMap;
}
