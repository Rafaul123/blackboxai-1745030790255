const fetch = require('node-fetch');

class ApiScanner {
  constructor(apiUrl) {
    this.apiUrl = apiUrl;
    this.interval = null;
    this.packetBatch = [];
    this.packetCount = 0;
  }

  async fetchNetworkData() {
    try {
      const response = await fetch(this.apiUrl);
      if (!response.ok) {
        console.error('Failed to fetch network data:', response.statusText);
        return [];
      }
      const data = await response.json();
      return data.packets || [];
    } catch (error) {
      console.error('Error fetching network data:', error);
      return [];
    }
  }

  start(callback, summaryCallback) {
    this.interval = setInterval(async () => {
      const packets = await this.fetchNetworkData();
      packets.forEach(packet => {
        callback(packet);
        this.packetBatch.push(packet);
        this.packetCount++;
      });

      if (this.packetCount >= 10) {
        const summary = this.generateSummary(this.packetBatch);
        if (summaryCallback) {
          summaryCallback(summary);
        }
        this.packetBatch = [];
        this.packetCount = 0;
      }
    }, 2000);
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

module.exports = ApiScanner;
