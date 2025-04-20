console.log('Starting network scan with dynamic new IP detection and enhanced threat analysis...');

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

let unknownExternalCount = 0;
const unknownExternalMap = {};

let newDeviceCount = 0;
const newDeviceMap = {};

let packetCount = 0;
let protocolCounts = {
  TCP: 0,
  UDP: 0,
  ICMP: 0,
  HTTP: 0,
  HTTPS: 0,
};

function isPrivateIP(ip) {
  const privateRanges = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'];
  return privateRanges.some(prefix => ip.startsWith(prefix));
}

function isKnownDeveloperSource(ip) {
  return ip === '8.8.8.8' || ip === '1.1.1.1';
}

function detectMITMAttack(data) {
  if (data.src === data.dst && data.srcSource !== data.dstSource) {
    return true;
  }
  if (['RST', 'FIN'].includes(data.packetDetails.flags) && data.protocol === 'TCP') {
    return true;
  }
  return false;
}

function getThreatLevelAndDescription(data) {
  let level = 'none';
  let description = 'Normal network activity detected.';
  let severity = 0;
  let advice = 'No action needed.';
  let mitm = false;

  const srcIsKnownDev = isKnownDeveloperSource(data.src);
  const dstIsKnownDev = isKnownDeveloperSource(data.dst);

  if (!protocols.includes(data.protocol)) {
    level = 'hazardous';
    description = 'Unknown protocol detected, potential unauthorized communication.';
    severity = 9;
    advice = 'Investigate the source immediately and consider blocking the IP.';
  }

  if (data.packetDetails.flags === 'RST' && data.packetDetails.flags === 'FIN') {
    level = 'hazardous';
    description = 'Suspicious TCP flags combination detected, possible connection hijacking or reset attack.';
    severity = 10;
    advice = 'Isolate the affected device and perform a full security audit.';
  }

  if (data.length > 1400) {
    level = level === 'hazardous' ? 'hazardous' : 'dangerous';
    description = 'Large packet size detected, could indicate data exfiltration or flooding attack.';
    severity = level === 'hazardous' ? 9 : 7;
    advice = 'Monitor traffic closely and consider rate limiting or firewall rules.';
  }

  const srcIsUnknownExternal = data.srcSource && data.srcSource.startsWith('Unknown External');
  const dstIsUnknownExternal = data.dstSource && data.dstSource.startsWith('Unknown External');

  if (!srcIsKnownDev && !dstIsKnownDev) {
    if (srcIsUnknownExternal && isPrivateIP(data.dst)) {
      level = level === 'hazardous' ? 'hazardous' : 'dangerous';
      description = 'Unknown external source making direct contact with the network.';
      severity = level === 'hazardous' ? 9 : 7;
      advice = 'Investigate and consider blocking suspicious external sources.';
    } else if (dstIsUnknownExternal && isPrivateIP(data.src)) {
      level = level === 'hazardous' ? 'hazardous' : 'dangerous';
      description = 'Unknown external destination receiving data from the network, possible data gathering.';
      severity = level === 'hazardous' ? 9 : 7;
      advice = 'Monitor outgoing traffic and secure sensitive data.';
    } else if (!isPrivateIP(data.src) || !isPrivateIP(data.dst)) {
      level = level === 'hazardous' ? 'hazardous' : 'dangerous';
      description = 'Communication with external IP detected, monitor for unauthorized access or firewall breaches.';
      severity = level === 'hazardous' ? 9 : 6;
      advice = 'Verify the legitimacy of external connections and update firewall policies.';
    }
  }

  if (data.packetDetails.ttl <= 5) {
    level = level === 'hazardous' ? 'hazardous' : 'suspicious';
    description = 'Very low TTL detected, possible scanning or reconnaissance activity.';
    severity = level === 'hazardous' ? 8 : 4;
    advice = 'Increase monitoring and consider intrusion detection systems.';
  }

  mitm = detectMITMAttack(data);

  return { level, description, severity, advice, mitm };
}

function getSourceName(ip) {
  const entry = ips.find((item) => item.ip === ip);
  if (entry) {
    if (entry.source === 'Unknown External') {
      if (!unknownExternalMap[ip]) {
        unknownExternalCount++;
        unknownExternalMap[ip] = `Unknown External ${unknownExternalCount}`;
      }
      return unknownExternalMap[ip];
    }
    return entry.source;
  } else {
    if (!newDeviceMap[ip]) {
      newDeviceCount++;
      newDeviceMap[ip] = `New Device ${newDeviceCount}`;
      console.log(`🆕 New device detected: ${ip} assigned as ${newDeviceMap[ip]}`);
    }
    return newDeviceMap[ip];
  }
}

function generateNetworkData() {
  const protocol = protocols[Math.floor(Math.random() * protocols.length)];
  packetCount++;
  protocolCounts[protocol]++;

  const allIPs = ips.map(item => item.ip).concat(Object.keys(newDeviceMap));
  if (allIPs.length === 0) {
    allIPs.push('192.168.1.2');
  }
  const srcIP = allIPs[Math.floor(Math.random() * allIPs.length)];
  const dstIP = allIPs[Math.floor(Math.random() * allIPs.length)];

  return {
    timestamp: new Date().toISOString(),
    src: srcIP,
    srcSource: getSourceName(srcIP),
    dst: dstIP,
    dstSource: getSourceName(dstIP),
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
  const { level, description, severity, advice, mitm } = getThreatLevelAndDescription(data);
  if (mitm) {
    console.warn(`🛑 Possible Man-in-the-Middle (MITM) attack detected from ${data.srcSource}! Immediate investigation recommended.`);
  }
  if (level === 'suspicious') {
    console.warn(`⚠️ Suspicious network activity detected from ${data.srcSource}! Severity: ${severity}/10. Effect: Monitoring required. ${description} Advice: ${advice}`);
  } else if (level === 'dangerous') {
    console.warn(`🚨 Dangerous network activity detected from ${data.srcSource}! Severity: ${severity}/10. Effect: Possible firewall breach. ${description} Advice: ${advice}`);
  } else if (level === 'hazardous') {
    console.warn(`🔥 Hazardous network activity detected from ${data.srcSource}! Severity: ${severity}/10. Effect: Potential remote code execution (RCE) or severe compromise. ${description} Advice: ${advice}`);
  }
}, 2000);

setInterval(() => {
  printSummary();
}, 600000);
