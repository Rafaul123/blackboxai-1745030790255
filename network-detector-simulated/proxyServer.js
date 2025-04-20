const http = require('http');
const httpProxy = require('http-proxy');
const WebSocket = require('ws');

// Create a proxy server
const proxy = httpProxy.createProxyServer({});

// Create a simple HTTP server to listen for requests and proxy them
const server = http.createServer((req, res) => {
  // Log request details for analysis
  const requestData = {
    method: req.method,
    url: req.url,
    headers: req.headers,
    timestamp: new Date().toISOString(),
  };

  // Broadcast request data to WebSocket clients
  broadcast(JSON.stringify({ type: 'request', data: requestData }));

  // Proxy the request to the target
  proxy.web(req, res, { target: req.url, changeOrigin: true }, (err) => {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Bad Gateway: ' + err.message);
  });
});

// WebSocket server for sending analysis data to frontend
const wss = new WebSocket.Server({ noServer: true });

let clients = [];

wss.on('connection', (ws) => {
  clients.push(ws);
  ws.on('close', () => {
    clients = clients.filter((client) => client !== ws);
  });
});

function broadcast(message) {
  clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// Upgrade HTTP server to handle WebSocket connections
server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

const PORT = 8080;
server.listen(PORT, () => {
  console.log(`Proxy server listening on port ${PORT}`);
});

module.exports = { server, wss };
