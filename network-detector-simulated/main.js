
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const networkMonitor = require('../networkMonitor');
const { server } = require('./proxyServer');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, '../preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  // Start network monitoring and send data to renderer
  networkMonitor.start(
    (data) => {
      if (mainWindow) {
        mainWindow.webContents.send('network-data', data);
      }
    },
    (summary) => {
      if (mainWindow) {
        mainWindow.webContents.send('scan-summary', summary);
      }
    }
  );

  // Start the proxy server for live network capture
  server.listen(8080, () => {
    console.log('Proxy server started on port 8080');
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// Add --no-sandbox flag to fix running as root issue
app.commandLine.appendSwitch('no-sandbox');

app.on('window-all-closed', () => {
  networkMonitor.stop();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
