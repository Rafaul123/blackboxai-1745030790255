class FfupScanner {
  constructor() {
    this.interval = null;
    this.packetBatch = [];
    this.packetCount = 0;
  }

  start(callback, summaryCallback) {
    // Simulate ffup scanning by generating dummy packets every second
    this.interval = setInterval(() => {
      const packet = this.generateDummyPacket();
      callback(packet);
      this.packetBatch.push(packet);
      this.packetCount++;

      if (this.packetCount >= 10) {
        const summary = this.generateSummary(this.packetBatch);
        if (summaryCallback) {
          summaryCallback(summary);
        }
        this.packetBatch = [];
        this.packetCount = 0;
      }
    }, 1000);
  }

  generateDummyPacket() {
    const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'];
    const sources = ['Home WiFi', 'Office Network', 'VPN', 'Unknown External'];
    const destinations = ['Google DNS', 'Cloudflare DNS', 'Unknown External', 'VPN', 'Home WiFi'];

    return {
      timestamp: new Date().toISOString(),
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      source: sources[Math.floor(Math.random() * sources.length)],
      destination: destinations[Math.floor(Math.random() * destinations.length)],
      length: Math.floor(Math.random() * 1500) + 40,
      flags: ['ACK', 'SYN', 'FIN', 'RST'][Math.floor(Math.random() * 4)],
      ttl: Math.floor(Math.random() * 128) + 1,
      windowSize: Math.floor(Math.random() * 65535),
      checksum: Math.floor(Math.random() * 65535),
      description: '',
      severity: 0,
      advice: '',
    };
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
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }
}

module.exports = FfupScanner;
