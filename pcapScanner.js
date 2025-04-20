const pcap = require('pcap');

class PcapScanner {
  constructor() {
    this.session = null;
    this.packetBatch = [];
    this.packetCount = 0;
    this.interval = null;
  }

  start(callback, summaryCallback) {
    try {
      this.session = pcap.createSession('', 'ip');
    } catch (error) {
      console.error('Failed to create pcap session:', error);
      return;
    }

    this.session.on('packet', (rawPacket) => {
      const packet = pcap.decode.packet(rawPacket);
      // Extract relevant info from packet
      const data = this.parsePacket(packet);
      if (data) {
        callback(data);
        this.packetBatch.push(data);
        this.packetCount++;
      }
    });

    this.interval = setInterval(() => {
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

  parsePacket(packet) {
    try {
      const ip = packet.payload.payload;
      const tcp = ip.payload;
      return {
        timestamp: new Date().toISOString(),
        protocol: ip.protocol_name,
        source: ip.saddr.toString(),
        destination: ip.daddr.toString(),
        length: ip.total_length,
        flags: tcp ? tcp.flags : '',
        ttl: ip.ttl,
        windowSize: tcp ? tcp.window_size : 0,
        checksum: tcp ? tcp.checksum : 0,
        description: '',
        severity: 0,
        advice: '',
      };
    } catch (error) {
      console.error('Error parsing packet:', error);
      return null;
    }
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
    if (this.session) {
      this.session.close();
      this.session = null;
    }
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }
}

module.exports = PcapScanner;
