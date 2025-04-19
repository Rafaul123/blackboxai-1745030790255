const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const networkMonitor = require('./networkMonitor');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile('renderer/index.html');

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  // Start network monitoring and send data to renderer
  networkMonitor.start((data) => {
    if (mainWindow) {
      mainWindow.webContents.send('network-data', data);
    }
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  networkMonitor.stop();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC handlers if needed can be added here
