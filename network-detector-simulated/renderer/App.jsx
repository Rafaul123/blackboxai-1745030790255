import React, { useEffect, useState } from 'react';
import { analyzeNetworkData } from '../../analysisModule.js';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts';

export default function App() {
  const [networkData, setNetworkData] = useState([]);
  const [attackSurfaceData, setAttackSurfaceData] = useState([]);
  const [protocolData, setProtocolData] = useState([]);
  const [scanSummary, setScanSummary] = useState(null);

  useEffect(() => {
    window.electronAPI.onNetworkData((data) => {
      setNetworkData((prev) => {
        const newData = [data, ...prev].slice(0, 100); // Keep last 100 entries

        // Prepare data for analysis
        const analysisInput = newData.map((entry) => ({
          protocol: entry.protocol,
          description: entry.description || '', // fallback if description missing
        }));

        const { attackSurfaceCounts, protocolCounts } = analyzeNetworkData(analysisInput);

        // Format data for recharts
        const attackSurfaceArray = Object.entries(attackSurfaceCounts).map(([key, value]) => ({
          name: key,
          count: value,
        }));

        const protocolArray = Object.entries(protocolCounts).map(([key, value]) => ({
          name: key,
          count: value,
        }));

        setAttackSurfaceData(attackSurfaceArray);
        setProtocolData(protocolArray);

        return newData;
      });
    });

    window.electronAPI.onScanSummary((summary) => {
      setScanSummary(summary);
    });
  }, []);

  return (
    <div className="p-4">
      <h1 className="text-3xl font-bold mb-6">Network Detector App</h1>

      <div className="mb-8">
        <h2 className="text-xl font-semibold mb-4">Attack Surface Analysis</h2>
        {attackSurfaceData.length === 0 ? (
          <p className="text-gray-500">No attack surface data available.</p>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <BarChart
              data={attackSurfaceData}
              margin={{
                top: 5, right: 30, left: 20, bottom: 5,
              }}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" fill="#8884d8" />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="mb-8">
        <h2 className="text-xl font-semibold mb-4">Protocol Analysis</h2>
        {protocolData.length === 0 ? (
          <p className="text-gray-500">No protocol data available.</p>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <BarChart
              data={protocolData}
              margin={{
                top: 5, right: 30, left: 20, bottom: 5,
              }}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" fill="#82ca9d" />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

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
                  <td className="border border-gray-300 px-2 py-1">{entry.source}</td>
                  <td className="border border-gray-300 px-2 py-1">{entry.destination}</td>
                  <td className="border border-gray-300 px-2 py-1">{entry.protocol}</td>
                  <td className="border border-gray-300 px-2 py-1">{entry.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {scanSummary && (
        <div className="bg-gray-100 rounded p-4 mt-6">
          <h2 className="text-xl font-semibold mb-4">Scan Summary</h2>
          <p>Total Packets: {scanSummary.totalPackets}</p>
          <p>Alerts Detected: {scanSummary.alerts}</p>
          <div className="grid grid-cols-3 gap-4 mt-4">
            <div>
              <h3 className="font-semibold">Protocols</h3>
              <ul>
                {Object.entries(scanSummary.protocols).map(([protocol, count]) => (
                  <li key={protocol}>{protocol}: {count}</li>
                ))}
              </ul>
            </div>
            <div>
              <h3 className="font-semibold">Sources</h3>
              <ul>
                {Object.entries(scanSummary.sources).map(([source, count]) => (
                  <li key={source}>{source}: {count}</li>
                ))}
              </ul>
            </div>
            <div>
              <h3 className="font-semibold">Destinations</h3>
              <ul>
                {Object.entries(scanSummary.destinations).map(([destination, count]) => (
                  <li key={destination}>{destination}: {count}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
