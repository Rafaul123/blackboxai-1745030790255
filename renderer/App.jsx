import React, { useEffect, useState } from 'react';

export default function App() {
  const [networkData, setNetworkData] = useState([]);

  useEffect(() => {
    window.electronAPI.onNetworkData((data) => {
      setNetworkData((prev) => [data, ...prev].slice(0, 100)); // Keep last 100 entries
    });
  }, []);

  return (
    <div>
      <h1 className="text-3xl font-bold mb-6">Network Detector App</h1>
      <div className="bg-white shadow rounded p-4 max-h-[400px] overflow-auto">
        {networkData.length === 0 ? (
          <p className="text-gray-500">No network data detected yet.</p>
        ) : (
          <table className="w-full table-auto border-collapse border border-gray-300">
            <thead>
              <tr className="bg-gray-200">
                <th className="border border-gray-300 px-2 py-1 text-left">Timestamp</th>
                <th className="border border-gray-300 px-2 py-1 text-left">Source IP</th>
                <th className="border border-gray-300 px-2 py-1 text-left">Destination IP</th>
                <th className="border border-gray-300 px-2 py-1 text-left">Protocol</th>
                <th className="border border-gray-300 px-2 py-1 text-left">Length</th>
              </tr>
            </thead>
            <tbody>
              {networkData.map((entry, index) => (
                <tr key={index} className="hover:bg-gray-100">
                  <td className="border border-gray-300 px-2 py-1">{entry.timestamp}</td>
                  <td className="border border-gray-300 px-2 py-1">{entry.src}</td>
                  <td className="border border-gray-300 px-2 py-1">{entry.dst}</td>
                  <td className="border border-gray-300 px-2 py-1">{entry.protocol}</td>
                  <td className="border border-gray-300 px-2 py-1">{entry.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
