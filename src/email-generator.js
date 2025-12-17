/**
 * Abuse email message generator
 */

/**
 * Format a date for email headers
 * @returns {string} - RFC 2822 formatted date
 */
function formatDate() {
  return new Date().toUTCString();
}

/**
 * Generate email subject line
 * @param {object[]} ipInfos - Array of IP information objects
 * @returns {string} - Email subject
 */
function generateSubject(ipInfos) {
  const ipCount = ipInfos.length;
  const orgName = ipInfos[0]?.orgName || 'your network';

  if (ipCount === 1) {
    return `Abuse Report: Malicious activity from ${ipInfos[0].ip}`;
  }
  return `Abuse Report: Malicious activity from ${ipCount} IPs in ${orgName}`;
}

/**
 * Generate email body
 * @param {object[]} ipInfos - Array of IP information objects
 * @param {Map<string, string[]>} ipLogMap - Map of IP -> log entries
 * @param {object} options - Generation options
 * @returns {string} - Email body
 */
function generateBody(ipInfos, ipLogMap, options = {}) {
  const {
    senderOrg = 'System Administrator',
    maxLogsPerIP = 50,
  } = options;

  const lines = [];

  lines.push('Dear Abuse Team,');
  lines.push('');
  lines.push(`We have detected malicious activity originating from IP address(es) under your administration.`);
  lines.push('We kindly request that you investigate this matter and take appropriate action.');
  lines.push('');
  lines.push('='.repeat(70));
  lines.push('INCIDENT DETAILS');
  lines.push('='.repeat(70));
  lines.push('');
  lines.push(`Report generated: ${formatDate()}`);
  lines.push(`Number of offending IPs: ${ipInfos.length}`);
  lines.push('');

  for (const info of ipInfos) {
    lines.push('-'.repeat(70));
    lines.push(`IP Address: ${info.ip}`);
    if (info.netRange) {
      lines.push(`Network Range: ${info.netRange}`);
    }
    if (info.country) {
      lines.push(`Country: ${info.country}`);
    }
    if (info.orgName && info.orgName !== 'Unknown') {
      lines.push(`Organization: ${info.orgName}`);
    }
    lines.push('');

    const logs = ipLogMap.get(info.ip) || [];
    const displayLogs = logs.slice(0, maxLogsPerIP);

    if (displayLogs.length > 0) {
      lines.push('Relevant log entries:');
      lines.push('');
      for (const log of displayLogs) {
        lines.push(`  ${log}`);
      }
      if (logs.length > maxLogsPerIP) {
        lines.push(`  ... and ${logs.length - maxLogsPerIP} more entries`);
      }
      lines.push('');
    }
  }

  lines.push('='.repeat(70));
  lines.push('');
  lines.push('Please take appropriate action to address this issue. If you require');
  lines.push('additional information or log samples, please do not hesitate to contact us.');
  lines.push('');
  lines.push('Thank you for your cooperation in maintaining a safe internet environment.');
  lines.push('');
  lines.push('Best regards,');
  lines.push(senderOrg);

  return lines.join('\n');
}

/**
 * Generate a complete email message
 * @param {string} abuseEmail - Recipient abuse email
 * @param {object[]} ipInfos - Array of IP information objects
 * @param {Map<string, string[]>} ipLogMap - Map of IP -> log entries
 * @param {object} options - Generation options
 * @returns {object} - Email message object
 */
export function generateEmail(abuseEmail, ipInfos, ipLogMap, options = {}) {
  const {
    senderEmail = 'abuse@example.com',
    senderName = 'Abuse Reporter',
    ...bodyOptions
  } = options;

  return {
    to: abuseEmail,
    from: `${senderName} <${senderEmail}>`,
    subject: generateSubject(ipInfos),
    body: generateBody(ipInfos, ipLogMap, bodyOptions),
    ips: ipInfos.map(i => i.ip),
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Format email for stdout output
 * @param {object} email - Email object from generateEmail
 * @returns {string} - Formatted email string
 */
export function formatEmailForOutput(email) {
  const lines = [];

  lines.push('=' .repeat(78));
  lines.push('ABUSE REPORT EMAIL');
  lines.push('='.repeat(78));
  lines.push('');
  lines.push(`To: ${email.to}`);
  lines.push(`From: ${email.from}`);
  lines.push(`Subject: ${email.subject}`);
  lines.push(`Date: ${email.generatedAt}`);
  lines.push(`IPs: ${email.ips.join(', ')}`);
  lines.push('');
  lines.push('-'.repeat(78));
  lines.push('MESSAGE BODY');
  lines.push('-'.repeat(78));
  lines.push('');
  lines.push(email.body);
  lines.push('');

  return lines.join('\n');
}

/**
 * Generate all abuse emails from grouped data
 * @param {Map<string, object[]>} abuseGroups - Map of abuseEmail -> IP infos
 * @param {Map<string, string[]>} ipLogMap - Map of IP -> log entries
 * @param {object} options - Generation options
 * @returns {object[]} - Array of email objects
 */
export function generateAllEmails(abuseGroups, ipLogMap, options = {}) {
  const emails = [];

  for (const [abuseEmail, ipInfos] of abuseGroups) {
    // Skip unknown abuse contacts or create separate handling
    if (abuseEmail === 'unknown@unknown') {
      continue;
    }

    const email = generateEmail(abuseEmail, ipInfos, ipLogMap, options);
    emails.push(email);
  }

  return emails;
}

/**
 * Generate summary of IPs without abuse contacts
 * @param {Map<string, object[]>} abuseGroups - Map of abuseEmail -> IP infos
 * @returns {string|null} - Summary string or null if none
 */
export function generateUnknownIPsSummary(abuseGroups) {
  const unknownGroup = abuseGroups.get('unknown@unknown');
  if (!unknownGroup || unknownGroup.length === 0) {
    return null;
  }

  const lines = [];
  lines.push('='.repeat(78));
  lines.push('IPs WITHOUT ABUSE CONTACT INFORMATION');
  lines.push('='.repeat(78));
  lines.push('');
  lines.push('The following IPs could not be matched to an abuse contact:');
  lines.push('');

  for (const info of unknownGroup) {
    lines.push(`  ${info.ip}`);
    if (info.orgName && info.orgName !== 'Unknown') {
      lines.push(`    Organization: ${info.orgName}`);
    }
    if (info.error) {
      lines.push(`    Error: ${info.error}`);
    }
  }

  lines.push('');
  lines.push('You may need to manually look up abuse contacts for these IPs.');
  lines.push('');

  return lines.join('\n');
}
