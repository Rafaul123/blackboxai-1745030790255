console.log('Starting network scan with enhanced threat levels, source identification, and detailed descriptions...');

const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'];
const ips = [
  { ip: '192.168.1.2', source: 'Home WiFi' },
  { ip: '10.0.0.5', source: 'Office Network' },
  { ip: '172.16.0.3', source: 'VPN' },
  { ip: '8.8.8.8', source: 'Google DNS' },
  { ip: '1.1.1.1', source: 'Cloudflare DNS' },
  { ip: '203.0.113.5', source: 'Unknown External' },
  { ip: '198.51.100.7', source: 'Unknown External' },
];

let packetCount = 0;
let protocolCounts = {
  TCP: 0,
  UDP: 0,
  ICMP: 0,
  HTTP: 0,
  HTTPS: 0,
};

function getThreatLevelAndDescription(data) {
  // Determine threat level and description
  const privateRanges = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'];
  const isPrivate = (ip) => privateRanges.some(prefix => ip.startsWith(prefix));

  let level = 'none';
  let description = 'Normal network activity detected.';

  // Unknown protocol
  if (!protocols.includes(data.protocol)) {
    level = 'hazardous';
    description = 'Unknown protocol detected, potential unauthorized communication.';
  }

  // Suspicious flags combination (e.g., RST with FIN)
  if (data.packetDetails.flags === 'RST' && data.packetDetails.flags === 'FIN') {
    level = 'hazardous';
    description = 'Suspicious TCP flags combination detected, possible connection hijacking or reset attack.';
  }

  // Large packet size > 1400 bytes
  if (data.length > 1400) {
    level = level === 'hazardous' ? 'hazardous' : 'dangerous';
    description = 'Large packet size detected, could indicate data exfiltration or flooding attack.';
  }

  // External IPs (not in private ranges)
  if (!isPrivate(data.src) || !isPrivate(data.dst)) {
    level = level === 'hazardous' ? 'hazardous' : 'dangerous';
    description = 'Communication with external IP detected, monitor for unauthorized access or firewall breaches.';
  }

  // TTL very low (<=5) could be suspicious
  if (data.packetDetails.ttl <= 5) {
    level = level === 'hazardous' ? 'hazardous' : 'suspicious';
    description = 'Very low TTL detected, possible scanning or reconnaissance activity.';
  }

  return { level, description };
}

function getSourceName(ip) {
  const entry = ips.find((item) => item.ip === ip);
  return entry ? entry.source : 'Unknown Source';
}

function generateNetworkData() {
  const protocol = protocols[Math.floor(Math.random() * protocols.length)];
  packetCount++;
  protocolCounts[protocol]++;

  const srcEntry = ips[Math.floor(Math.random() * ips.length)];
  const dstEntry = ips[Math.floor(Math.random() * ips.length)];

  return {
    timestamp: new Date().toISOString(),
    src: srcEntry.ip,
    srcSource: srcEntry.source,
    dst: dstEntry.ip,
    dstSource: dstEntry.source,
    protocol: protocol,
    length: Math.floor(Math.random() * 1500) + 40,
    packetDetails: {
      flags: ['SYN', 'ACK', 'FIN', 'RST'][Math.floor(Math.random() * 4)],
      ttl: Math.floor(Math.random() * 128) + 1,
      windowSize: Math.floor(Math.random() * 65535) + 1,
      checksum: Math.floor(Math.random() * 65535) + 1,
    },
  };
}

function formatData(data) {
  return `\n[${data.timestamp}] ${data.protocol} packet from ${data.src} (${data.srcSource}) to ${data.dst} (${data.dstSource}) (Length: ${data.length} bytes)
Flags: ${data.packetDetails.flags}, TTL: ${data.packetDetails.ttl}, Window Size: ${data.packetDetails.windowSize}, Checksum: ${data.packetDetails.checksum}`;
}

function printSummary() {
  console.log('\n=== 10 Minute Summary ===');
  console.log(`Total packets: ${packetCount}`);
  for (const protocol of protocols) {
    console.log(`  ${protocol}: ${protocolCounts[protocol]}`);
  }
  console.log('========================\n');

  // Reset counts
  packetCount = 0;
  protocolCounts = {
    TCP: 0,
    UDP: 0,
    ICMP: 0,
    HTTP: 0,
    HTTPS: 0,
  };
}

setInterval(() => {
  const data = generateNetworkData();
  console.log(formatData(data));
  const { level, description } = getThreatLevelAndDescription(data);
  if (level === 'suspicious') {
    console.warn(`⚠️ Suspicious network activity detected from ${data.srcSource}! Effect: Monitoring required. ${description}`);
  } else if (level === 'dangerous') {
    console.warn(`🚨 Dangerous network activity detected from ${data.srcSource}! Effect: Possible firewall breach. ${description}`);
  } else if (level === 'hazardous') {
    console.warn(`🔥 Hazardous network activity detected from ${data.srcSource}! Effect: Potential remote code execution (RCE) or severe compromise. ${description}`);
  }
}, 2000);

// Print summary every 10 minutes (600000 ms)
setInterval(() => {
  printSummary();
}, 600000);
