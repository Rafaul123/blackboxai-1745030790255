

const path = require('path');
const http = require('http');
const express = require('express');

const ApiScanner = require('./apiScanner');
const PcapScanner = require('./pcapScanner');
const FfupScanner = require('./ffupScanner');

const SCANNER_TYPE = process.env.SCANNER_TYPE || 'api'; // 'pcap', 'ffup', or 'api'
const apiUrl = 'https://example.com/api/network-data'; // Replace with actual API URL

let scanner;

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'renderer')));

app.get('/api/scan-summary', (req, res) => {
  res.json(latestSummary || {});
});

app.get('/api/network-data', (req, res) => {
  res.json(latestData || {});
});

let latestSummary = null;
let latestData = null;

function startScanner() {
  if (SCANNER_TYPE === 'pcap') {
    scanner = new PcapScanner();
  } else if (SCANNER_TYPE === 'ffup') {
    scanner = new FfupScanner();
  } else {
    scanner = new ApiScanner(apiUrl);
  }

  scanner.start(
    (data) => {
      latestData = data;
      console.log('Network Data:', data);
    },
    (summary) => {
      latestSummary = summary;
      console.log('Scan Summary:', summary);
    }
  );
}

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  startScanner();
});

process.on('SIGINT', () => {
  console.log('Stopping scanner...');
  if (scanner) {
    scanner.stop();
  }
  process.exit();
});


