import assert from 'assert';
import { classifySingleTarget, validateTargets } from '../server/targetValidator';
import { parseNmapXml } from '../server/xmlParser';
import { normalizeScanResults } from '../server/resultNormalizer';
import { checkNmapAvailability, buildNmapArgs, validatePortSpecification } from '../server/nmapService';
import { initDatabase, dbSaveScan, dbGetScan, dbListScans, dbDeleteScan } from '../server/database';
import { scanManager } from '../server/scanManager';
import { ScanJob } from '../server/types';

async function runAllTests() {
  console.log('====================================================');
  console.log('RUNNING AUTOMATED SECURITY & SCANNER TEST SUITE');
  console.log('====================================================');

  let passed = 0;
  let total = 0;

  function test(name: string, fn: () => void | Promise<void>) {
    total++;
    return Promise.resolve()
      .then(() => fn())
      .then(() => {
        console.log(`  ✓ PASS: ${name}`);
        passed++;
      })
      .catch((err) => {
        console.error(`  ✗ FAIL: ${name}`);
        console.error(`    ${err.message}`);
      });
  }

  // 1. Target Validation Tests
  await test('Target Validation: Standard IPv4 loopback', () => {
    const c = classifySingleTarget('127.0.0.1');
    assert.strictEqual(c.isValid, true);
    assert.strictEqual(c.category, 'loopback');
    assert.strictEqual(c.isExternal, false);
  });

  await test('Target Validation: RFC 1918 Private IPv4', () => {
    const c = classifySingleTarget('192.168.1.10');
    assert.strictEqual(c.isValid, true);
    assert.strictEqual(c.category, 'private');
    assert.strictEqual(c.isExternal, false);
  });

  await test('Target Validation: Valid CIDR /24', () => {
    const c = classifySingleTarget('192.168.1.0/24');
    assert.strictEqual(c.isValid, true);
    assert.strictEqual(c.type, 'cidr');
  });

  await test('Target Validation: Public FQDN and Hostname', () => {
    const c = classifySingleTarget('scanme.nmap.org');
    assert.strictEqual(c.isValid, true);
    assert.strictEqual(c.category, 'public');
    assert.strictEqual(c.isExternal, true);
  });

  await test('Security: Reject shell command injection (semicolon)', () => {
    const c = classifySingleTarget('192.168.1.1; rm -rf /');
    assert.strictEqual(c.isValid, false);
  });

  await test('Security: Reject command substitution ($(...))', () => {
    const c = classifySingleTarget('$(whoami)');
    assert.strictEqual(c.isValid, false);
  });

  await test('Security: Reject backtick injection (`id`)', () => {
    const c = classifySingleTarget('`id`');
    assert.strictEqual(c.isValid, false);
  });

  await test('Security: Reject newline injection', () => {
    const c = classifySingleTarget('192.168.1.1\nwhoami');
    assert.strictEqual(c.isValid, false);
  });

  await test('Port Specification: Valid single, list, and range', () => {
    assert.strictEqual(validatePortSpecification('22').isValid, true);
    assert.strictEqual(validatePortSpecification('22,80,443').isValid, true);
    assert.strictEqual(validatePortSpecification('1-1000').isValid, true);
    assert.strictEqual(validatePortSpecification('-p-').isValid, true);
    assert.strictEqual(validatePortSpecification('22; rm -rf').isValid, false);
    assert.strictEqual(validatePortSpecification('99999').isValid, false);
  });

  // 2. Nmap Availability
  await test('Nmap Availability & Detection', async () => {
    const status = await checkNmapAvailability();
    console.log(`     Detected: ${status.version}`);
    assert.strictEqual(status.available, true);
    assert.ok(status.version.includes('Nmap'));
  });

  // 3. Argument Construction Safety
  await test('Nmap Safe Argument Builder: No Shell Injection', () => {
    const { args } = buildNmapArgs(['192.168.1.1'], 'Quick', 'T4', undefined, '/tmp/test.xml');
    assert.ok(args.includes('-T4'));
    assert.ok(args.includes('--top-ports'));
    assert.ok(args.includes('192.168.1.1'));
    // Ensure no raw shell characters
    for (const a of args) {
      assert.strictEqual(/[;&|`]/.test(a), false);
    }
  });

  // 4. XML Parser with realistic fixture
  const sampleXml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -p 22,80 -oX sample.xml 192.168.1.50" start="1700000000" version="7.93">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <hostnames>
      <hostname name="gateway.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu" method="probed"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" method="probed"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1700000005" elapsed="5.2" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>`;

  await test('XML Parser: Extract hosts, ports, and services', () => {
    const parsed = parseNmapXml(sampleXml);
    assert.strictEqual(parsed.hosts.length, 1);
    assert.strictEqual(parsed.hosts[0].address, '192.168.1.50');
    assert.strictEqual(parsed.hosts[0].hostname, 'gateway.local');
    assert.strictEqual(parsed.hosts[0].ports.length, 2);
    assert.strictEqual(parsed.hosts[0].ports[0].portId, 22);
    assert.strictEqual(parsed.hosts[0].ports[0].serviceName, 'ssh');
    assert.strictEqual(parsed.hosts[0].ports[0].product, 'OpenSSH');
    assert.strictEqual(parsed.hosts[0].ports[1].portId, 80);
  });

  // 5. Result Normalization & Provenance
  await test('Result Normalizer: Preserves Measured Data and Provenance', () => {
    const parsed = parseNmapXml(sampleXml);
    const normalized = normalizeScanResults(
      'scan_test_1',
      parsed,
      ['192.168.1.50'],
      'Standard',
      'nmap -sT -p 22,80 192.168.1.50',
      new Date(1700000000000).toISOString(),
      new Date(1700000005200).toISOString()
    );

    assert.strictEqual(normalized.hosts.length, 1);
    const h = normalized.hosts[0];
    assert.strictEqual(h.address.source, 'measured');
    assert.strictEqual(h.address.value, '192.168.1.50');
    assert.strictEqual(h.status.value, 'up');
    assert.strictEqual(h.status.source, 'measured');
    assert.strictEqual(h.ports[0].state.value, 'open');
    assert.strictEqual(h.ports[0].state.source, 'measured');
    assert.strictEqual(h.ports[0].service.value, 'ssh');
    assert.strictEqual(h.ports[0].service.source, 'measured');

    // OS is estimated from Ubuntu banner
    assert.strictEqual(h.os[0].source, 'estimated');
    assert.ok(h.os[0].value.includes('Ubuntu'));

    // Risk score is derived
    assert.strictEqual(h.riskScore.source, 'derived');
  });

  // 6. SQLite Database
  await test('Database: Save, Retrieve, List, and Delete Scans', async () => {
    await initDatabase();
    const testJob: ScanJob = {
      id: `test_${Date.now()}`,
      status: 'completed',
      createdAt: new Date().toISOString(),
      targetRaw: '127.0.0.1',
      validatedTargets: ['127.0.0.1'],
      isPublicTargetConfirmed: true,
      profile: 'Quick',
      timing: 'T4',
      nmapArgs: ['-sT'],
      commandDisplay: 'nmap -sT 127.0.0.1',
      logs: ['Log line 1', 'Log line 2'],
      summary: {
        hostsScanned: 1,
        hostsUp: 1,
        hostsDown: 0,
        openPorts: 1,
        closedPorts: 99,
        filteredPorts: 0,
        unknownPorts: 0,
        elapsedSeconds: 2,
        startTime: new Date().toISOString(),
        finishTime: new Date().toISOString(),
        nmapVersion: 'Nmap 7.93',
        commandExecuted: 'nmap -sT 127.0.0.1',
      },
    };

    await dbSaveScan(testJob);
    const retrieved = await dbGetScan(testJob.id);
    assert.ok(retrieved);
    assert.strictEqual(retrieved.id, testJob.id);

    const list = await dbListScans(10);
    assert.ok(list.some((s) => s.id === testJob.id));

    await dbDeleteScan(testJob.id);
    const deleted = await dbGetScan(testJob.id);
    assert.strictEqual(deleted, null);
  });

  // 7. Scan Comparison Diff Engine
  await test('Comparison Engine: Calculates Port & Service Changes', async () => {
    const jobA: ScanJob = {
      id: 'scan_comp_a',
      status: 'completed',
      createdAt: '2026-01-01T00:00:00Z',
      targetRaw: '10.0.0.5',
      validatedTargets: ['10.0.0.5'],
      isPublicTargetConfirmed: true,
      profile: 'Standard',
      timing: 'T3',
      nmapArgs: [],
      commandDisplay: '',
      logs: [],
      results: {
        scanId: 'scan_comp_a',
        status: 'completed',
        startedAt: '2026-01-01T00:00:00Z',
        completedAt: '2026-01-01T00:01:00Z',
        profile: 'Standard',
        targets: ['10.0.0.5'],
        summary: {
          hostsScanned: 1,
          hostsUp: 1,
          hostsDown: 0,
          openPorts: 1,
          closedPorts: 999,
          filteredPorts: 0,
          unknownPorts: 0,
          elapsedSeconds: 60,
          startTime: '',
          finishTime: '',
          nmapVersion: '7.93',
          commandExecuted: '',
        },
        hosts: [
          {
            address: { value: '10.0.0.5', source: 'measured' },
            ipType: 'ipv4',
            isPrivate: true,
            status: { value: 'up', source: 'measured' },
            ports: [
              {
                port: 22,
                protocol: 'tcp',
                state: { value: 'open', source: 'measured' },
                service: { value: 'ssh', source: 'measured' },
                version: { value: '7.4', source: 'measured' },
              },
            ],
            os: [],
            riskScore: { value: 20, source: 'derived' },
            riskLevel: 'low',
          },
        ],
        riskObservations: [],
      },
    };

    const jobB: ScanJob = {
      id: 'scan_comp_b',
      status: 'completed',
      createdAt: '2026-01-02T00:00:00Z',
      targetRaw: '10.0.0.5',
      validatedTargets: ['10.0.0.5'],
      isPublicTargetConfirmed: true,
      profile: 'Standard',
      timing: 'T3',
      nmapArgs: [],
      commandDisplay: '',
      logs: [],
      results: {
        scanId: 'scan_comp_b',
        status: 'completed',
        startedAt: '2026-01-02T00:00:00Z',
        completedAt: '2026-01-02T00:01:00Z',
        profile: 'Standard',
        targets: ['10.0.0.5'],
        summary: {
          hostsScanned: 1,
          hostsUp: 1,
          hostsDown: 0,
          openPorts: 2,
          closedPorts: 998,
          filteredPorts: 0,
          unknownPorts: 0,
          elapsedSeconds: 60,
          startTime: '',
          finishTime: '',
          nmapVersion: '7.93',
          commandExecuted: '',
        },
        hosts: [
          {
            address: { value: '10.0.0.5', source: 'measured' },
            ipType: 'ipv4',
            isPrivate: true,
            status: { value: 'up', source: 'measured' },
            ports: [
              {
                port: 22,
                protocol: 'tcp',
                state: { value: 'open', source: 'measured' },
                service: { value: 'ssh', source: 'measured' },
                version: { value: '8.9', source: 'measured' }, // version changed
              },
              {
                port: 8080,
                protocol: 'tcp',
                state: { value: 'open', source: 'measured' }, // new port
                service: { value: 'http-proxy', source: 'measured' },
              },
            ],
            os: [],
            riskScore: { value: 45, source: 'derived' },
            riskLevel: 'medium',
          },
        ],
        riskObservations: [],
      },
    };

    await dbSaveScan(jobA);
    await dbSaveScan(jobB);

    const diff = await scanManager.compareScans('scan_comp_a', 'scan_comp_b');
    assert.ok(diff);
    assert.strictEqual(diff.newOpenPorts.length, 1);
    assert.strictEqual(diff.newOpenPorts[0].port, 8080);
    assert.strictEqual(diff.serviceChanges.length, 1);
    assert.strictEqual(diff.serviceChanges[0].oldVersion, '7.4');
    assert.strictEqual(diff.serviceChanges[0].newVersion, '8.9');

    await dbDeleteScan('scan_comp_a');
    await dbDeleteScan('scan_comp_b');
  });

  console.log('====================================================');
  console.log(`TEST SUITE COMPLETED: ${passed}/${total} PASSED`);
  console.log('====================================================');

  if (passed !== total) {
    process.exit(1);
  }
}

runAllTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
