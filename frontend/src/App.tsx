import { useState, useEffect } from 'react';
import { ScanNetwork, SaveSettings, LoadSettings, StopScan, GenerateHTMLReport, GetSavedReports, OpenReport, DeleteReport } from "../wailsjs/go/main/App";
import { EventsOn, EventsOff, Quit, WindowMinimise } from "../wailsjs/runtime/runtime";
import './App.css';

interface ScanResult {
  ip: string; hostname: string; port: string; service: string; banner: string; mac: string; vendor: string; os: string;
}

interface ReportFile {
  name: string; path: string; date: string; size: string; type: string;
}

function App() {
  const [activeView, setActiveView] = useState('scanner');
  const [activeSettingsTab, setActiveSettingsTab] = useState('engine');

  // Scanner
  const [target, setTarget] = useState("192.168.1.0/24");
  const [portProfile, setPortProfile] = useState("top15");
  const [ports, setPorts] = useState("21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080");
  const [showInfo, setShowInfo] = useState(true);
  const [usePingSweep, setUsePingSweep] = useState(true);
  const [scanIntensity, setScanIntensity] = useState("normal");
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<ScanResult[]>([]);

  // Paramètres
  const [timeoutMs, setTimeoutMs] = useState(500);
  const [maxThreads, setMaxThreads] = useState(500);
  const [highContrast, setHighContrast] = useState(false);
  const [uiSize, setUiSize] = useState("Normale (100%)");
  const [defaultExportPath, setDefaultExportPath] = useState("C:\\Exports\\OmniTool");
  const [autoExportFormat, setAutoExportFormat] = useState("none");
  const [saveMessage, setSaveMessage] = useState("");

  // Historique
  const [savedReports, setSavedReports] = useState<ReportFile[]>([]);

  useEffect(() => {
    LoadSettings().then((settings: any) => {
      setTimeoutMs(settings.timeoutMs); setMaxThreads(settings.maxThreads); setHighContrast(settings.highContrast);
      setUiSize(settings.uiSize); setDefaultExportPath(settings.defaultExportPath); setAutoExportFormat(settings.autoExportFormat || "none");
    });
  }, []);

  useEffect(() => {
    if (activeView === 'reports') { refreshReportsList(); }
  }, [activeView, defaultExportPath]);

  useEffect(() => {
    EventsOn("port_found", (newResult: ScanResult) => { setResults(prev => [...prev, newResult]); });
    return () => { EventsOff("port_found"); };
  }, []);

  const refreshReportsList = async () => {
    const list = await GetSavedReports(defaultExportPath);
    setSavedReports(list || []);
  };

  const handleProfileChange = (e: any) => {
    const val = e.target.value; setPortProfile(val);
    if (val === "top15") setPorts("21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080");
    else if (val === "system") setPorts("1-1024");
    else if (val === "full") setPorts("1-65535");
  };

  const startScan = async () => {
    setIsScanning(true); setResults([]); 
    let finalTimeout = Number(timeoutMs);
    let finalThreads = Number(maxThreads);

    if (scanIntensity === "stealth") {
      finalTimeout = 1500;
      finalThreads = 10;
    } else if (scanIntensity === "aggressive") {
      finalTimeout = 200;
      finalThreads = 2000;
    }

    try { await ScanNetwork(target, ports, showInfo, usePingSweep, finalTimeout, finalThreads, defaultExportPath, autoExportFormat); } 
    catch (error) { console.error(error); } finally { setIsScanning(false); }
  };

  const handleSaveSettings = async () => {
    const settings = { timeoutMs: Number(timeoutMs), maxThreads: Number(maxThreads), reduceAnim: false, highContrast, uiSize, defaultExportPath, autoExportFormat };
    const msg = await SaveSettings(settings);
    setSaveMessage(msg);
    setTimeout(() => setSaveMessage(""), 3000);
  };

  return (
    <div id="App" className={`${highContrast ? 'high-contrast-mode' : ''} ${uiSize === 'Grande (125%)' ? 'ui-large-mode' : ''}`}>
      <nav className="sidebar">
        <div className="brand">
          <h2>OmniTool</h2>
          {/* VERSION MISE A JOUR EN v1.0.1 */}
          <span className="version">v1.0.1</span>
        </div>
        <ul className="nav-links">
          <li className={activeView === 'scanner' ? 'active' : ''} onClick={() => setActiveView('scanner')}>[ RECONNAISSANCE ]</li>
          <li className={activeView === 'audit' ? 'active' : ''} onClick={() => setActiveView('audit')}>[ AUDIT SYSTEME ]</li>
          <li className={activeView === 'reports' ? 'active' : ''} onClick={() => setActiveView('reports')}><span>[ LOGS & HISTORIQUE ]</span></li>
          <li className={activeView === 'settings' ? 'active' : ''} onClick={() => setActiveView('settings')}><span>[ CONFIGURATION ]</span></li>
        </ul>
      </nav>

      <main className="main-content">
        <header className="topbar drag-region">
          <h1>
            {activeView === 'scanner' && "NETWORK RECONNAISSANCE ENGINE"}
            {activeView === 'audit' && "LOCAL AUDIT MODULE"}
            {activeView === 'reports' && "DATA CENTER MANAGEMENT"}
            {activeView === 'settings' && "GLOBAL ENGINE CONFIGURATION"}
          </h1>
          <div className="window-controls no-drag">
            <button onClick={WindowMinimise}>-</button>
            <button className="close-btn" onClick={Quit}>X</button>
          </div>
        </header>

        {activeView === 'scanner' && (
          <div className="view-content">
            <div className="control-panel">
              <div className="input-group"><label>TARGET NETBLOCK (IP/CIDR)</label><input type="text" value={target} onChange={(e) => setTarget(e.target.value)} /></div>
              <div style={{ display: 'flex', gap: '15px', width: '100%' }}>
                <div className="input-group" style={{ flex: 1 }}><label>PORT RANGE PROFILE</label><select value={portProfile} onChange={handleProfileChange}><option value="top15">Top 15 Essentials</option><option value="system">Privileged (1-1024)</option><option value="full">Complete (1-65535)</option><option value="custom">Manual Definition</option></select></div>
                <div className="input-group" style={{ flex: 2 }}><label>PORT LIST / ARRAY</label><input type="text" value={ports} onChange={(e) => { setPorts(e.target.value); setPortProfile("custom"); }} /></div>
              </div>
              
              <div style={{ display: 'flex', gap: '30px', alignItems: 'flex-end', width: '100%', marginTop: '10px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div className="checkbox-group"><input type="checkbox" id="ping-sweep" checked={usePingSweep} onChange={(e) => setUsePingSweep(e.target.checked)} /><label htmlFor="ping-sweep">Enable Ping Sweep (Ignore Dead Hosts)</label></div>
                  <div className="checkbox-group"><input type="checkbox" id="info-check" checked={showInfo} onChange={(e) => setShowInfo(e.target.checked)} /><label htmlFor="info-check">Deep Inspection (Banners & Hostnames)</label></div>
                </div>
                <div className="input-group" style={{ maxWidth: '200px' }}>
                  <label>SCAN INTENSITY</label>
                  <select value={scanIntensity} onChange={(e) => setScanIntensity(e.target.value)}>
                    <option value="stealth">STEALTH (Slow/Undetected)</option>
                    <option value="normal">NORMAL (Default Config)</option>
                    <option value="aggressive">AGGRESSIVE (Hard/Fast)</option>
                  </select>
                </div>
                <div className="input-group" style={{ maxWidth: '150px' }}>
                  <label>AUTOMATIC EXPORT</label>
                  <select value={autoExportFormat} onChange={(e) => setAutoExportFormat(e.target.value)}><option value="none">Disabled</option><option value="csv">CSV Format</option><option value="html">HTML Format</option><option value="both">CSV + HTML</option></select>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '15px', marginTop: '20px' }}>
                {!isScanning ? (<button className="scan-btn" onClick={startScan}>EXECUTE TARGET SCAN</button>) : (<><button className="scan-btn scanning" disabled>SCANNING NETWORK...</button><button className="scan-btn stop-btn" onClick={() => StopScan()}>HALT SCAN ENGINE</button></>)}
                {!isScanning && results.length > 0 && autoExportFormat === 'none' && (<button className="scan-btn manual-btn" onClick={() => GenerateHTMLReport(results, defaultExportPath)}>COMPILE MANUAL HTML REPORT</button>)}
              </div>
            </div>

            <div className="results-container">
              {results.length > 0 ? (
                <table className="results-table">
                  <thead><tr><th>TARGET HOST</th><th>PORT</th><th>OPERATING SYSTEM</th><th>HARDWARE INFORMATION / MAC</th><th>SERVICE</th><th>BANNER METADATA</th></tr></thead>
                  <tbody>{results.map((res, idx) => (<tr key={idx}><td className="ip-cell"><strong>{res.ip}</strong>{res.hostname !== "-" && <span className="hostname"><br/>{res.hostname}</span>}</td><td className="port-cell"><span className="badge">OPEN // {res.port}</span></td><td>{res.os}</td><td><div>{res.vendor}</div><div className="mac-text">{res.mac}</div></td><td>{res.service}</td><td className="banner-cell">{res.banner}</td></tr>))}</tbody>
                </table>
              ) : (<div className="empty-state">{!isScanning && <p>SYSTEM STATUS: IDLE. AWAITING TARGET INPUT.</p>}</div>)}
            </div>
          </div>
        )}

        {activeView === 'reports' && (
          <div className="view-content">
            <div className="control-panel" style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <label style={{ fontSize: '0.8rem', color: '#888', letterSpacing: '2px', fontWeight: 'bold' }}>SAVED DATA DIRECTORY</label>
                <span style={{ fontFamily: 'monospace', fontSize: '1.05rem', color: 'var(--accent)' }}>{defaultExportPath}</span>
              </div>
              <button className="scan-btn" onClick={refreshReportsList}>REFRESH LIST</button>
            </div>
            <div className="results-container" style={{ marginTop: '20px' }}>
              {savedReports.length > 0 ? (
                <table className="results-table">
                  <thead><tr><th>FILE IDENTIFIER</th><th>EXTENSION</th><th>TIMESTAMP</th><th>FILE SIZE</th><th>ACTIONS</th></tr></thead>
                  <tbody>{savedReports.map((file, idx) => (<tr key={idx}><td><strong>{file.name}</strong></td><td><span className="badge">{file.type}</span></td><td>{file.date}</td><td>{file.size}</td><td style={{ display: 'flex', gap: '10px' }}><button className="action-row-btn" onClick={() => OpenReport(file.path)}>LAUNCH</button><button className="action-row-btn delete-btn" onClick={async () => { await DeleteReport(file.path); refreshReportsList(); }}>PURGE</button></td></tr>))}</tbody>
                </table>
              ) : (<div className="empty-state"><p>NO HISTORICAL DATA FOUND IN STORAGE.</p></div>)}
            </div>
          </div>
        )}

        {activeView === 'settings' && (
          <div className="view-content">
            <div style={{ display: 'flex', gap: '20px', marginBottom: '25px', borderBottom: '1px solid #1f1f23', paddingBottom: '10px' }}>
              <button className={`tab-btn ${activeSettingsTab === 'engine' ? 'active' : ''}`} onClick={() => setActiveSettingsTab('engine')}>NETWORK SETTINGS</button>
              <button className={`tab-btn ${activeSettingsTab === 'interface' ? 'active' : ''}`} onClick={() => setActiveSettingsTab('interface')}>VISUAL SETTINGS</button>
              <button className={`tab-btn ${activeSettingsTab === 'export' ? 'active' : ''}`} onClick={() => setActiveSettingsTab('export')}>STORAGE SETTINGS</button>
            </div>
            <div className="control-panel" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
              {activeSettingsTab === 'engine' && (<><div className="input-group" style={{ marginBottom: '15px' }}><label>TCP HANDSHAKE TIMEOUT (MS)</label><input type="number" value={timeoutMs} onChange={(e) => setTimeoutMs(Number(e.target.value))} /></div><div className="input-group" style={{ marginBottom: '20px' }}><label>CONCURRENT SEMAPHORE LIMIT (THREADS)</label><input type="number" value={maxThreads} onChange={(e) => setMaxThreads(Number(e.target.value))} /></div></>)}
              {activeSettingsTab === 'interface' && (<div style={{ padding: '20px', border: '1px dashed #333', width: '100%', textAlign: 'center' }}><h3 style={{ color: '#888', letterSpacing: '2px', margin: '0 0 10px 0' }}>MODULE OFFLINE</h3><p style={{ color: '#555', fontFamily: 'monospace', margin: 0 }}>Visual customization deployment is scheduled for v1.2.0.</p></div>)}
              {activeSettingsTab === 'export' && (<><div className="input-group" style={{ marginBottom: '20px', width: '100%' }}><label>TARGET CONSOLE EXPORT PATH</label><input type="text" value={defaultExportPath} onChange={(e) => setDefaultExportPath(e.target.value)} /></div></>)}
              {activeSettingsTab !== 'interface' && (<div style={{ display: 'flex', gap: '15px', alignItems: 'center', marginTop: '15px' }}><button className="scan-btn" onClick={handleSaveSettings}>WRITE CHANGES</button>{saveMessage && <span style={{ color: 'var(--accent)', fontFamily: 'monospace' }}>{saveMessage}</span>}</div>)}
            </div>
          </div>
        )}
        {activeView === 'audit' && (<div className="view-content empty-view"><h2>CRITICAL MODULE OFFLINE</h2><p>Local audit mechanisms are pending compilation.</p></div>)}
      </main>
    </div>
  );
}

export default App;