import { describe, it } from 'node:test';
import assert from 'node:assert';
import { extractIPs, isPrivateIP, buildIPLogMap } from './ip-extractor.js';

describe('extractIPs', () => {
  it('extracts IPv4 addresses from log line', () => {
    const line = 'Failed password for root from 192.0.2.1 port 22 ssh2';
    const ips = extractIPs(line);
    assert.deepStrictEqual(ips, ['192.0.2.1']);
  });

  it('extracts multiple IPv4 addresses', () => {
    const line = 'Connection from 203.0.113.5 to 198.51.100.10 established';
    const ips = extractIPs(line);
    assert.deepStrictEqual(ips, ['203.0.113.5', '198.51.100.10']);
  });

  it('extracts IPv6 addresses', () => {
    const line = 'Failed login from 2001:db8:85a3:0000:0000:8a2e:0370:7334';
    const ips = extractIPs(line);
    assert.strictEqual(ips.length, 1);
    assert.strictEqual(ips[0], '2001:db8:85a3:0000:0000:8a2e:0370:7334');
  });

  it('returns empty array when no IPs found', () => {
    const line = 'System started successfully';
    const ips = extractIPs(line);
    assert.deepStrictEqual(ips, []);
  });

  it('handles edge case IPv4 addresses', () => {
    const line = 'IPs: 0.0.0.0 and 255.255.255.255';
    const ips = extractIPs(line);
    assert.deepStrictEqual(ips, ['0.0.0.0', '255.255.255.255']);
  });

  it('does not match invalid IPv4 addresses', () => {
    const line = 'Invalid IP: 256.1.1.1 or 1.2.3.999';
    const ips = extractIPs(line);
    assert.deepStrictEqual(ips, []);
  });
});

describe('isPrivateIP', () => {
  describe('IPv4 private ranges', () => {
    it('identifies 10.x.x.x as private', () => {
      assert.strictEqual(isPrivateIP('10.0.0.1'), true);
      assert.strictEqual(isPrivateIP('10.255.255.255'), true);
    });

    it('identifies 172.16-31.x.x as private', () => {
      assert.strictEqual(isPrivateIP('172.16.0.1'), true);
      assert.strictEqual(isPrivateIP('172.31.255.255'), true);
      assert.strictEqual(isPrivateIP('172.15.0.1'), false);
      assert.strictEqual(isPrivateIP('172.32.0.1'), false);
    });

    it('identifies 192.168.x.x as private', () => {
      assert.strictEqual(isPrivateIP('192.168.0.1'), true);
      assert.strictEqual(isPrivateIP('192.168.255.255'), true);
    });

    it('identifies loopback addresses as private', () => {
      assert.strictEqual(isPrivateIP('127.0.0.1'), true);
      assert.strictEqual(isPrivateIP('127.255.255.255'), true);
    });

    it('identifies link-local addresses as private', () => {
      assert.strictEqual(isPrivateIP('169.254.0.1'), true);
      assert.strictEqual(isPrivateIP('169.254.255.255'), true);
    });

    it('identifies CGNAT addresses as private', () => {
      assert.strictEqual(isPrivateIP('100.64.0.1'), true);
      assert.strictEqual(isPrivateIP('100.127.255.255'), true);
      assert.strictEqual(isPrivateIP('100.63.0.1'), false);
      assert.strictEqual(isPrivateIP('100.128.0.1'), false);
    });

    it('identifies 0.x.x.x as private', () => {
      assert.strictEqual(isPrivateIP('0.0.0.0'), true);
      assert.strictEqual(isPrivateIP('0.255.255.255'), true);
    });
  });

  describe('IPv6 private ranges', () => {
    it('identifies loopback ::1 as private', () => {
      assert.strictEqual(isPrivateIP('::1'), true);
    });

    it('identifies link-local fe80: as private', () => {
      assert.strictEqual(isPrivateIP('fe80:1234:5678::1'), true);
    });

    it('identifies unique local fc00: as private', () => {
      assert.strictEqual(isPrivateIP('fc00:1234::1'), true);
    });

    it('identifies unique local fd: as private', () => {
      assert.strictEqual(isPrivateIP('fd12:3456::1'), true);
    });
  });

  describe('public IPs', () => {
    it('identifies public IPv4 addresses correctly', () => {
      assert.strictEqual(isPrivateIP('8.8.8.8'), false);
      assert.strictEqual(isPrivateIP('203.0.113.1'), false);
      assert.strictEqual(isPrivateIP('198.51.100.1'), false);
      assert.strictEqual(isPrivateIP('1.1.1.1'), false);
    });

    it('identifies public IPv6 addresses correctly', () => {
      assert.strictEqual(isPrivateIP('2001:db8::1'), false);
      assert.strictEqual(isPrivateIP('2607:f8b0:4000::1'), false);
    });
  });
});

describe('buildIPLogMap', () => {
  it('builds map of IPs to log entries', () => {
    const lines = [
      'Failed password for root from 203.0.113.5 port 22',
      'Failed password for admin from 203.0.113.5 port 22',
      'Connection attempt from 198.51.100.10',
    ];

    const map = buildIPLogMap(lines);

    assert.strictEqual(map.size, 2);
    assert.deepStrictEqual(map.get('203.0.113.5'), [
      'Failed password for root from 203.0.113.5 port 22',
      'Failed password for admin from 203.0.113.5 port 22',
    ]);
    assert.deepStrictEqual(map.get('198.51.100.10'), [
      'Connection attempt from 198.51.100.10',
    ]);
  });

  it('excludes private IPs from the map', () => {
    const lines = [
      'Local connection from 192.168.1.1',
      'External attack from 203.0.113.5',
      'Loopback 127.0.0.1',
    ];

    const map = buildIPLogMap(lines);

    assert.strictEqual(map.size, 1);
    assert.strictEqual(map.has('192.168.1.1'), false);
    assert.strictEqual(map.has('127.0.0.1'), false);
    assert.strictEqual(map.has('203.0.113.5'), true);
  });

  it('returns empty map when no public IPs found', () => {
    const lines = [
      'Local connection from 192.168.1.1',
      'Loopback 127.0.0.1',
    ];

    const map = buildIPLogMap(lines);
    assert.strictEqual(map.size, 0);
  });

  it('returns empty map for empty input', () => {
    const map = buildIPLogMap([]);
    assert.strictEqual(map.size, 0);
  });

  it('handles lines without IPs', () => {
    const lines = [
      'System started',
      'Attack from 203.0.113.5',
      'Service stopped',
    ];

    const map = buildIPLogMap(lines);
    assert.strictEqual(map.size, 1);
    assert.deepStrictEqual(map.get('203.0.113.5'), ['Attack from 203.0.113.5']);
  });
});
