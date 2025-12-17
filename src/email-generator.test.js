import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  generateEmail,
  formatEmailForOutput,
  generateAllEmails,
  generateUnknownIPsSummary,
} from './email-generator.js';

describe('generateEmail', () => {
  it('generates email with correct structure', () => {
    const ipInfos = [
      { ip: '1.2.3.4', orgName: 'Test Org', netRange: '1.2.0.0/16', country: 'US' },
    ];
    const ipLogMap = new Map([
      ['1.2.3.4', ['Failed login from 1.2.3.4']],
    ]);

    const email = generateEmail('abuse@test.com', ipInfos, ipLogMap);

    assert.strictEqual(email.to, 'abuse@test.com');
    assert.ok(email.from.includes('Abuse Reporter'));
    assert.ok(email.subject.includes('1.2.3.4'));
    assert.ok(email.body.includes('1.2.3.4'));
    assert.ok(email.body.includes('Failed login from 1.2.3.4'));
    assert.deepStrictEqual(email.ips, ['1.2.3.4']);
    assert.ok(email.generatedAt);
  });

  it('generates email for multiple IPs', () => {
    const ipInfos = [
      { ip: '1.2.3.4', orgName: 'Test Org' },
      { ip: '1.2.3.5', orgName: 'Test Org' },
    ];
    const ipLogMap = new Map([
      ['1.2.3.4', ['Log entry 1']],
      ['1.2.3.5', ['Log entry 2']],
    ]);

    const email = generateEmail('abuse@test.com', ipInfos, ipLogMap);

    assert.ok(email.subject.includes('2 IPs'));
    assert.ok(email.subject.includes('Test Org'));
    assert.ok(email.body.includes('1.2.3.4'));
    assert.ok(email.body.includes('1.2.3.5'));
    assert.deepStrictEqual(email.ips, ['1.2.3.4', '1.2.3.5']);
  });

  it('respects custom sender options', () => {
    const ipInfos = [{ ip: '1.2.3.4', orgName: 'Test' }];
    const ipLogMap = new Map();

    const email = generateEmail('abuse@test.com', ipInfos, ipLogMap, {
      senderEmail: 'security@mycompany.com',
      senderName: 'Security Team',
      senderOrg: 'My Company Security',
    });

    assert.strictEqual(email.from, 'Security Team <security@mycompany.com>');
    assert.ok(email.body.includes('My Company Security'));
  });

  it('truncates log entries at maxLogsPerIP', () => {
    const ipInfos = [{ ip: '1.2.3.4', orgName: 'Test' }];
    const logs = Array(100).fill(0).map((_, i) => `Log entry ${i}`);
    const ipLogMap = new Map([['1.2.3.4', logs]]);

    const email = generateEmail('abuse@test.com', ipInfos, ipLogMap, { maxLogsPerIP: 10 });

    assert.ok(email.body.includes('Log entry 0'));
    assert.ok(email.body.includes('Log entry 9'));
    assert.ok(!email.body.includes('Log entry 50'));
    assert.ok(email.body.includes('and 90 more entries'));
  });

  it('includes network details when available', () => {
    const ipInfos = [{
      ip: '1.2.3.4',
      orgName: 'Test Org',
      netRange: '1.2.0.0 - 1.2.255.255',
      country: 'DE',
    }];
    const ipLogMap = new Map();

    const email = generateEmail('abuse@test.com', ipInfos, ipLogMap);

    assert.ok(email.body.includes('Network Range: 1.2.0.0 - 1.2.255.255'));
    assert.ok(email.body.includes('Country: DE'));
    assert.ok(email.body.includes('Organization: Test Org'));
  });
});

describe('formatEmailForOutput', () => {
  it('formats email with all headers', () => {
    const email = {
      to: 'abuse@test.com',
      from: 'Reporter <reporter@example.com>',
      subject: 'Abuse Report',
      body: 'Email body content',
      ips: ['1.2.3.4', '5.6.7.8'],
      generatedAt: '2024-01-15T10:00:00.000Z',
    };

    const output = formatEmailForOutput(email);

    assert.ok(output.includes('To: abuse@test.com'));
    assert.ok(output.includes('From: Reporter <reporter@example.com>'));
    assert.ok(output.includes('Subject: Abuse Report'));
    assert.ok(output.includes('IPs: 1.2.3.4, 5.6.7.8'));
    assert.ok(output.includes('Email body content'));
    assert.ok(output.includes('ABUSE REPORT EMAIL'));
    assert.ok(output.includes('MESSAGE BODY'));
  });
});

describe('generateAllEmails', () => {
  it('generates emails for all abuse groups', () => {
    const abuseGroups = new Map([
      ['abuse@provider1.com', [{ ip: '1.2.3.4', orgName: 'Provider1' }]],
      ['abuse@provider2.com', [{ ip: '5.6.7.8', orgName: 'Provider2' }]],
    ]);
    const ipLogMap = new Map([
      ['1.2.3.4', ['Log 1']],
      ['5.6.7.8', ['Log 2']],
    ]);

    const emails = generateAllEmails(abuseGroups, ipLogMap);

    assert.strictEqual(emails.length, 2);
    assert.ok(emails.some(e => e.to === 'abuse@provider1.com'));
    assert.ok(emails.some(e => e.to === 'abuse@provider2.com'));
  });

  it('skips unknown@unknown group', () => {
    const abuseGroups = new Map([
      ['abuse@provider.com', [{ ip: '1.2.3.4', orgName: 'Provider' }]],
      ['unknown@unknown', [{ ip: '5.6.7.8', orgName: 'Unknown' }]],
    ]);
    const ipLogMap = new Map();

    const emails = generateAllEmails(abuseGroups, ipLogMap);

    assert.strictEqual(emails.length, 1);
    assert.strictEqual(emails[0].to, 'abuse@provider.com');
  });

  it('returns empty array when only unknown contacts', () => {
    const abuseGroups = new Map([
      ['unknown@unknown', [{ ip: '1.2.3.4' }]],
    ]);
    const ipLogMap = new Map();

    const emails = generateAllEmails(abuseGroups, ipLogMap);

    assert.strictEqual(emails.length, 0);
  });

  it('returns empty array for empty groups', () => {
    const abuseGroups = new Map();
    const ipLogMap = new Map();

    const emails = generateAllEmails(abuseGroups, ipLogMap);

    assert.strictEqual(emails.length, 0);
  });

  it('passes options to generateEmail', () => {
    const abuseGroups = new Map([
      ['abuse@test.com', [{ ip: '1.2.3.4', orgName: 'Test' }]],
    ]);
    const ipLogMap = new Map();

    const emails = generateAllEmails(abuseGroups, ipLogMap, {
      senderEmail: 'custom@example.com',
      senderName: 'Custom Sender',
    });

    assert.strictEqual(emails.length, 1);
    assert.strictEqual(emails[0].from, 'Custom Sender <custom@example.com>');
  });
});

describe('generateUnknownIPsSummary', () => {
  it('generates summary for unknown IPs', () => {
    const abuseGroups = new Map([
      ['unknown@unknown', [
        { ip: '1.2.3.4', orgName: 'Unknown Org' },
        { ip: '5.6.7.8', orgName: 'Unknown' },
      ]],
    ]);

    const summary = generateUnknownIPsSummary(abuseGroups);

    assert.ok(summary);
    assert.ok(summary.includes('IPs WITHOUT ABUSE CONTACT'));
    assert.ok(summary.includes('1.2.3.4'));
    assert.ok(summary.includes('5.6.7.8'));
    assert.ok(summary.includes('Unknown Org'));
    assert.ok(summary.includes('manually look up'));
  });

  it('returns null when no unknown IPs', () => {
    const abuseGroups = new Map([
      ['abuse@provider.com', [{ ip: '1.2.3.4' }]],
    ]);

    const summary = generateUnknownIPsSummary(abuseGroups);

    assert.strictEqual(summary, null);
  });

  it('returns null for empty groups', () => {
    const abuseGroups = new Map();

    const summary = generateUnknownIPsSummary(abuseGroups);

    assert.strictEqual(summary, null);
  });

  it('returns null when unknown group is empty', () => {
    const abuseGroups = new Map([
      ['unknown@unknown', []],
    ]);

    const summary = generateUnknownIPsSummary(abuseGroups);

    assert.strictEqual(summary, null);
  });

  it('includes error info when available', () => {
    const abuseGroups = new Map([
      ['unknown@unknown', [
        { ip: '1.2.3.4', orgName: 'Unknown', error: 'WHOIS timeout' },
      ]],
    ]);

    const summary = generateUnknownIPsSummary(abuseGroups);

    assert.ok(summary.includes('1.2.3.4'));
    assert.ok(summary.includes('Error: WHOIS timeout'));
  });
});
