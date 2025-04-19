const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  onNetworkData: (callback) => ipcRenderer.on('network-data', (event, data) => callback(data))
});
