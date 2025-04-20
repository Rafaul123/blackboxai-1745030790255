/**
 * analysisModule.js
 * Module to analyze network scan data and map to OWASP attack surfaces.
 */

const OWASP_ATTACK_SURFACES = {
  'Injection': ['Unauthorized communication', 'Connection hijacking', 'Reset attack'],
  'Broken Authentication': ['Possible Man-in-the-Middle (MITM) attack'],
  'Sensitive Data Exposure': ['Data exfiltration', 'Data gathering', 'Large packet size'],
  'Security Misconfiguration': ['Firewall breach', 'Unauthorized access', 'Firewall policies'],
  'Information Disclosure': ['Scanning or reconnaissance activity', 'Very low TTL detected'],
  'Denial of Service': ['Flooding attack'],
  'Other': []
};

/**
 * Map threat description to OWASP attack surface category.
 * @param {string} description - Threat description from network data.
 * @returns {string} OWASP attack surface category.
 */
function mapDescriptionToOWASP(description) {
  for (const [category, keywords] of Object.entries(OWASP_ATTACK_SURFACES)) {
    for (const keyword of keywords) {
      if (description.includes(keyword)) {
        return category;
      }
    }
  }
  return 'Other';
}

/**
 * Analyze network data entries.
 * @param {Array} dataEntries - Array of network data objects with fields: protocol, description, severity, advice.
 * @returns {Object} Aggregated analysis with counts by attack surface, protocol, and detailed packet info.
 */
function analyzeNetworkData(dataEntries) {
  const attackSurfaceCounts = {};
  const protocolCounts = {};
  const detailedPackets = [];

  for (const entry of dataEntries) {
    const category = mapDescriptionToOWASP(entry.description);
    attackSurfaceCounts[category] = (attackSurfaceCounts[category] || 0) + 1;

    const protocol = entry.protocol || 'Unknown';
    protocolCounts[protocol] = (protocolCounts[protocol] || 0) + 1;

    detailedPackets.push({
      timestamp: entry.timestamp,
      source: entry.source,
      destination: entry.destination,
      protocol: protocol,
      length: entry.length,
      flags: entry.flags,
      ttl: entry.ttl,
      windowSize: entry.windowSize,
      checksum: entry.checksum,
      description: entry.description,
      severity: entry.severity || 0,
      advice: entry.advice || '',
      attackSurface: category,
    });
  }

  return { attackSurfaceCounts, protocolCounts, detailedPackets };
}

module.exports = {
  analyzeNetworkData,
  mapDescriptionToOWASP,
  OWASP_ATTACK_SURFACES,
};
