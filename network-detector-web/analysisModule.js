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
 * @param {Array} dataEntries - Array of network data objects with fields: protocol, description.
 * @returns {Object} Aggregated analysis with counts by attack surface and protocol.
 */
function analyzeNetworkData(dataEntries) {
  const attackSurfaceCounts = {};
  const protocolCounts = {};

  for (const entry of dataEntries) {
    const category = mapDescriptionToOWASP(entry.description);
    attackSurfaceCounts[category] = (attackSurfaceCounts[category] || 0) + 1;

    const protocol = entry.protocol || 'Unknown';
    protocolCounts[protocol] = (protocolCounts[protocol] || 0) + 1;
  }

  return { attackSurfaceCounts, protocolCounts };
}

export { analyzeNetworkData, mapDescriptionToOWASP, OWASP_ATTACK_SURFACES };
