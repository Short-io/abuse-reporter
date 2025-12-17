import { describe, it } from 'node:test';
import assert from 'node:assert';
import { groupByAbuseEmail } from './abuse-lookup.js';

describe('groupByAbuseEmail', () => {
  it('groups IPs by their abuse email', () => {
    const whoisResults = new Map([
      ['1.2.3.4', { ip: '1.2.3.4', abuseEmail: 'abuse@provider1.com', orgName: 'Provider1' }],
      ['1.2.3.5', { ip: '1.2.3.5', abuseEmail: 'abuse@provider1.com', orgName: 'Provider1' }],
      ['5.6.7.8', { ip: '5.6.7.8', abuseEmail: 'abuse@provider2.com', orgName: 'Provider2' }],
    ]);

    const groups = groupByAbuseEmail(whoisResults);

    assert.strictEqual(groups.size, 2);
    assert.strictEqual(groups.get('abuse@provider1.com').length, 2);
    assert.strictEqual(groups.get('abuse@provider2.com').length, 1);
  });

  it('groups IPs without abuse email under unknown@unknown', () => {
    const whoisResults = new Map([
      ['1.2.3.4', { ip: '1.2.3.4', abuseEmail: 'abuse@provider.com', orgName: 'Provider' }],
      ['5.6.7.8', { ip: '5.6.7.8', abuseEmail: null, orgName: 'Unknown' }],
      ['9.10.11.12', { ip: '9.10.11.12', abuseEmail: null, orgName: 'Also Unknown' }],
    ]);

    const groups = groupByAbuseEmail(whoisResults);

    assert.strictEqual(groups.size, 2);
    assert.strictEqual(groups.get('abuse@provider.com').length, 1);
    assert.strictEqual(groups.get('unknown@unknown').length, 2);
  });

  it('handles empty whois results', () => {
    const whoisResults = new Map();
    const groups = groupByAbuseEmail(whoisResults);
    assert.strictEqual(groups.size, 0);
  });

  it('preserves all whois info in grouped results', () => {
    const whoisResults = new Map([
      ['1.2.3.4', {
        ip: '1.2.3.4',
        abuseEmail: 'abuse@test.com',
        orgName: 'Test Org',
        netRange: '1.2.0.0 - 1.2.255.255',
        country: 'US',
      }],
    ]);

    const groups = groupByAbuseEmail(whoisResults);
    const groupedInfo = groups.get('abuse@test.com')[0];

    assert.strictEqual(groupedInfo.ip, '1.2.3.4');
    assert.strictEqual(groupedInfo.orgName, 'Test Org');
    assert.strictEqual(groupedInfo.netRange, '1.2.0.0 - 1.2.255.255');
    assert.strictEqual(groupedInfo.country, 'US');
  });

  it('handles all IPs having no abuse contact', () => {
    const whoisResults = new Map([
      ['1.2.3.4', { ip: '1.2.3.4', abuseEmail: null }],
      ['5.6.7.8', { ip: '5.6.7.8', abuseEmail: null }],
    ]);

    const groups = groupByAbuseEmail(whoisResults);

    assert.strictEqual(groups.size, 1);
    assert.strictEqual(groups.has('unknown@unknown'), true);
    assert.strictEqual(groups.get('unknown@unknown').length, 2);
  });

  it('handles single IP', () => {
    const whoisResults = new Map([
      ['8.8.8.8', { ip: '8.8.8.8', abuseEmail: 'network-abuse@google.com', orgName: 'Google LLC' }],
    ]);

    const groups = groupByAbuseEmail(whoisResults);

    assert.strictEqual(groups.size, 1);
    assert.strictEqual(groups.get('network-abuse@google.com').length, 1);
  });
});
