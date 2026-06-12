import { useState, useEffect } from 'react';
import { ScanNetwork, SaveSettings, LoadSettings, StopScan, GenerateHTMLReport, GetSavedReports, OpenReport, DeleteReport, RunSystemAudit, ExportAuditReport } from "../wailsjs/go/main/App";
import { EventsOn, EventsOff, Quit, WindowMinimise } from "../wailsjs/runtime/runtime";
import './App.css';

interface ScanResult {
  ip: string; hostname: string; port: string; service: string; banner: string; mac: string; vendor: string; os: string;
}

interface ReportFile {
  name: string; path: string; date: string; size: string; type: string;
}

interface AuditRow {
  category: string; control_name: string; status: string; result: string; recommendation: string; command: string;
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

  // Local Audit States
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditResults, setAuditResults] = useState<AuditRow[]>([]);
  const [auditMessage, setAuditMessage] = useState("");
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

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

  const startSystemAudit = async () => {
    setIsAuditing(true);
    setAuditResults([]);
    try {
      const res = await RunSystemAudit();
      setAuditResults(res || []);
    } catch (err) {
      console.error(err);
    } finally {
      setIsAuditing(false);
    }
  };

  const handleExportAudit = async () => {
    const msg = await ExportAuditReport(auditResults, defaultExportPath);
    setAuditMessage(msg);
    setTimeout(() => setAuditMessage(""), 4000);
  };

  const handleSaveSettings = async () => {
    const settings = { timeoutMs: Number(timeoutMs), maxThreads: Number(maxThreads), reduceAnim: false, highContrast, uiSize, defaultExportPath, autoExportFormat };
    const msg = await SaveSettings(settings);
    setSaveMessage(msg);
    setTimeout(() => setSaveMessage(""), 3000);
  };

  const getStatusColor = (status: string) => {
    if (status === "SECURE") return "#00ffcc";
    if (status === "WARNING") return "#f97316";
    return "#ef4444";
  };

  // Logique pour la copie du texte
  const copyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(cmd);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  // Calcul du Score de Conformité
  const secureCount = auditResults.filter(r => r.status === "SECURE").length;
  const complianceScore = auditResults.length > 0 ? Math.round((secureCount / auditResults.length) * 100) : 0;
  const scoreColor = complianceScore === 100 ? "#00ffcc" : complianceScore >= 50 ? "#f97316" : "#ef4444";

  return (
    <div id="App" className={`${highContrast ? 'high-contrast-mode' : ''} ${uiSize === 'Grande (125%)' ? 'ui-large-mode' : ''}`}>
      <nav className="sidebar">
        <div className="brand">
          <h2>OmniTool</h2>
          <span className="version">v1.1.0</span>
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
            {activeView === 'audit' && "LOCAL SECURITY AUDIT MODULE"}
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

        {activeView === 'audit' && (
          <div className="view-content">
            
            {/* LIGNE DU HAUT : Explications + Score de conformité */}
            <div style={{ display: 'flex', gap: '20px', marginBottom: '25px' }}>
              
              {/* Panneau de contrôle */}
              <div className="control-panel" style={{ flex: 2, margin: 0 }}>
                <div style={{ width: '100%' }}>
                  <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', letterSpacing: '1px', fontWeight: 'bold', display: 'block', marginBottom: '8px' }}>LOCAL ENVIRONMENT AUDIT SUB-SYSTEM</label>
                  <p style={{ margin: '0 0 15px 0', fontSize: '0.85rem', color: '#fff', fontFamily: 'monospace' }}>
                    This module queries host parameters to audit structural compliance. Run checks sequentially or in bulk.
                  </p>
                </div>
                <div style={{ display: 'flex', gap: '15px', alignItems: 'center', marginTop: '5px' }}>
                  <button className="scan-btn" onClick={startSystemAudit} disabled={isAuditing}>
                    {isAuditing ? "EVALUATING..." : "RUN SYSTEM AUDIT"}
                  </button>
                  {auditResults.length > 0 && !isAuditing && (
                    <button className="scan-btn manual-btn" onClick={handleExportAudit}>COMPILE REPORT</button>
                  )}
                  {auditMessage && <span style={{ color: 'var(--accent)', fontFamily: 'monospace', fontSize: '0.85rem' }}>{auditMessage}</span>}
                </div>
              </div>

              {/* Nouveau Score Visuel */}
              {auditResults.length > 0 && (
                <div style={{ flex: 1, backgroundColor: 'var(--bg-panel)', border: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px', gap: '20px' }}>
                  <div style={{ fontSize: '3rem', fontWeight: '900', color: scoreColor, fontFamily: 'Consolas, monospace' }}>
                    {complianceScore}%
                  </div>
                  <div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', letterSpacing: '2px', fontWeight: 'bold' }}>COMPLIANCE SCORE</div>
                    <div style={{ fontSize: '0.85rem', color: '#fff', marginTop: '5px', fontFamily: 'monospace' }}>
                      {secureCount} / {auditResults.length} CHECKS PASSED
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="results-container" style={{ margin: 0 }}>
              {auditResults.length > 0 ? (
                <table className="results-table">
                  <thead>
                    <tr>
                      <th style={{ width: '15%' }}>CATEGORY</th>
                      <th style={{ width: '25%' }}>CONTROL TARGET</th>
                      <th style={{ width: '15%' }}>COMPLIANCE STATUS</th>
                      <th style={{ width: '25%' }}>FINDINGS / CONSTAT</th>
                      <th style={{ width: '20%' }}>REMEDIATION / ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditResults.map((row, idx) => (
                      <tr key={idx}>
                        <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{row.category}</td>
                        <td><strong>{row.control_name}</strong></td>
                        <td>
                          <span style={{ color: getStatusColor(row.status), fontWeight: 'bold', letterSpacing: '1px' }}>
                            // {row.status}
                          </span>
                        </td>
                        <td>{row.result}</td>
                        <td style={{ color: '#cbd5e1', fontSize: '0.8rem', lineHeight: '1.4' }}>
                          <div style={{ marginBottom: row.command ? '8px' : '0' }}>{row.recommendation}</div>
                          
                          {/* BOUTON DE COPIE MAGIQUE */}
                          {row.command && (
                            <button 
                              onClick={() => copyCommand(row.command)}
                              style={{
                                background: copiedCmd === row.command ? 'var(--accent)' : 'transparent',
                                color: copiedCmd === row.command ? '#000' : 'var(--accent)',
                                border: '1px solid var(--accent)',
                                padding: '4px 10px',
                                fontSize: '0.7rem',
                                fontFamily: 'Consolas, monospace',
                                cursor: 'pointer',
                                fontWeight: 'bold',
                                transition: 'all 0.2s'
                              }}>
                              {copiedCmd === row.command ? "COPIED TO CLIPBOARD!" : "[ COPY FIX CMD ]"}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="empty-state">
                  <p>{isAuditing ? "GATHERING WMI AND LOCAL TERMINAL SECURITY TOKENS..." : "SYSTEM READY. AWAITING AUDIT INITIATION."}</p>
                </div>
              )}
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
      </main>
    </div>
  );
}

export default App;