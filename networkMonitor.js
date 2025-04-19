function start(callback) {
  // Simulate network data every 2 seconds for demo purposes
  const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'];
  const ips = ['192.168.1.2', '10.0.0.5', '172.16.0.3', '8.8.8.8', '1.1.1.1'];

  const interval = setInterval(() => {
    const data = {
      timestamp: new Date().toISOString(),
      src: ips[Math.floor(Math.random() * ips.length)],
      dst: ips[Math.floor(Math.random() * ips.length)],
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      length: Math.floor(Math.random() * 1500) + 40,
    };
    callback(data);
  }, 2000);

  return () => clearInterval(interval);
}

function stop() {
  // No-op for simulation
}

module.exports = {
  start,
  stop,
};
