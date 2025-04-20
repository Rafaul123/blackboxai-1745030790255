const EventEmitter = require('events');

class NetworkMonitor extends EventEmitter {
  constructor() {
    super();
    this.protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'];
    this.sources = ['Home WiFi', 'Office Network', 'VPN', 'Unknown External 1', 'Unknown External 2'];
    this.destinations = ['Google DNS', 'Cloudflare DNS', 'Unknown External 1', 'Unknown External 2', 'VPN', 'Home WiFi', 'Office Network'];
    this.attackDescriptions = [
      '',
      'Possible Man-in-the-Middle (MITM) attack detected',
      'Dangerous network activity detected',
      'Suspicious network activity detected',
    ];
  }

  start(callback, summaryCallback) {
    this.packetBatch = [];
    this.interval = setInterval(() => {
      const packet = this.generateRandomPacket();
      callback(packet);
      this.packetBatch.push(packet);
      this.emit('packet', packet);
    }, 1000);

    this.summaryInterval = setInterval(() => {
      if (this.packetBatch.length > 0) {
        const summary = this.generateSummary(this.packetBatch);
        if (summaryCallback) {
          summaryCallback(summary);
        }
        this.packetBatch = [];
      }
    }, 30000); // every 30 seconds
  }

  generateSummary(packets) {
    const summary = {
      totalPackets: packets.length,
      protocols: {},
      sources: {},
      destinations: {},
      alerts: 0,
    };
    packets.forEach((pkt) => {
      summary.protocols[pkt.protocol] = (summary.protocols[pkt.protocol] || 0) + 1;
      summary.sources[pkt.source] = (summary.sources[pkt.source] || 0) + 1;
      summary.destinations[pkt.destination] = (summary.destinations[pkt.destination] || 0) + 1;
      if (pkt.description && pkt.description.length > 0) {
        summary.alerts++;
      }
    });
    return summary;
  }

  stop() {
    clearInterval(this.interval);
  }

  generateRandomPacket() {
    const protocol = this.protocols[Math.floor(Math.random() * this.protocols.length)];
    const source = this.sources[Math.floor(Math.random() * this.sources.length)];
    const destination = this.destinations[Math.floor(Math.random() * this.destinations.length)];
    const length = Math.floor(Math.random() * 1500) + 40;
    const flags = ['ACK', 'SYN', 'FIN', 'RST', 'PSH', 'URG'][Math.floor(Math.random() * 6)];
    const ttl = Math.floor(Math.random() * 128) + 1;
    const windowSize = Math.floor(Math.random() * 65535);
    const checksum = Math.floor(Math.random() * 65535);
    const description = this.attackDescriptions[Math.floor(Math.random() * this.attackDescriptions.length)];

    return {
      timestamp: new Date().toISOString(),
      protocol,
      source,
      destination,
      length,
      flags,
      ttl,
      windowSize,
      checksum,
      description,
    };
  }
}

module.exports = new NetworkMonitor();
