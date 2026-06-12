package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx        context.Context
	scanCancel context.CancelFunc
	mu         sync.Mutex
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

type ScanResult struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Port     string `json:"port"`
	Service  string `json:"service"`
	Banner   string `json:"banner"`
	MAC      string `json:"mac"`
	Vendor   string `json:"vendor"`
	OS       string `json:"os"`
}

type AuditResult struct {
	Category       string `json:"category"`
	ControlName    string `json:"control_name"`
	Status         string `json:"status"` // SECURE, WARNING, VULNERABLE
	Result         string `json:"result"`
	Recommendation string `json:"recommendation"`
	Command        string `json:"command"`
}

type Settings struct {
	TimeoutMs         int    `json:"timeoutMs"`
	MaxThreads        int    `json:"maxThreads"`
	ReduceAnim        bool   `json:"reduceAnim"`
	HighContrast      bool   `json:"highContrast"`
	UISize            string `json:"uiSize"`
	DefaultExportPath string `json:"defaultExportPath"`
	AutoExportFormat  string `json:"autoExportFormat"`
}

type ReportFile struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Date string `json:"date"`
	Size string `json:"size"`
	Type string `json:"type"`
}

var knownServices = map[string]string{
	"21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
	"53": "DNS", "80": "HTTP", "110": "POP3", "135": "RPC", "139": "NetBIOS",
	"143": "IMAP", "443": "HTTPS", "445": "SMB", "3306": "MySQL",
	"3389": "RDP", "5432": "PostgreSQL", "8080": "HTTP-Alt",
}

func getConfigPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, "netbuddy_config.json")
}

func (a *App) LoadSettings() Settings {
	defaultSettings := Settings{TimeoutMs: 500, MaxThreads: 500, ReduceAnim: false, HighContrast: false, UISize: "Normale (100%)", DefaultExportPath: "C:\\Exports\\OmniTool", AutoExportFormat: "none"}
	data, err := os.ReadFile(getConfigPath())
	if err != nil {
		return defaultSettings
	}
	var loadedSettings Settings
	json.Unmarshal(data, &loadedSettings)
	if loadedSettings.AutoExportFormat == "" {
		loadedSettings.AutoExportFormat = "none"
	}
	return loadedSettings
}

func (a *App) SaveSettings(settings Settings) string {
	data, _ := json.MarshalIndent(settings, "", "  ")
	os.WriteFile(getConfigPath(), data, 0644)
	return "Paramètres sauvegardés !"
}

func (a *App) StopScan() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.scanCancel != nil {
		a.scanCancel()
	}
}

func (a *App) GetSavedReports(exportPath string) []ReportFile {
	var reports []ReportFile
	files, err := os.ReadDir(exportPath)
	if err != nil {
		return reports
	}
	for _, file := range files {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".csv") || strings.HasSuffix(file.Name(), ".html")) {
			info, _ := file.Info()
			fileType := "CSV"
			if strings.HasSuffix(file.Name(), ".html") {
				fileType = "HTML"
			}
			sizeKB := fmt.Sprintf("%d KB", info.Size()/1024)
			if info.Size() < 1024 {
				sizeKB = "1 KB"
			}
			reports = append(reports, ReportFile{Name: file.Name(), Path: filepath.Join(exportPath, file.Name()), Date: info.ModTime().Format("02/01/2006 15:04"), Size: sizeKB, Type: fileType})
		}
	}
	return reports
}

func (a *App) OpenReport(filePath string) string {
	cmd := exec.Command("cmd", "/c", "start", "", filePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Start()
	if err != nil {
		return "Erreur lors de l'ouverture."
	}
	return "Ouverture en cours..."
}

func (a *App) DeleteReport(filePath string) string {
	err := os.Remove(filePath)
	if err != nil {
		return "Erreur de suppression."
	}
	return "Fichier supprimé."
}

// --- LOGIQUE D'AUDIT SYSTEME MASSIVE (8 TESTS) ---
func (a *App) RunSystemAudit() []AuditResult {
	var audits []AuditResult

	// 1. FIREWALL
	cmdFirewall := exec.Command("netsh", "advfirewall", "show", "currentprofile", "state")
	cmdFirewall.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outFirewall, err := cmdFirewall.Output()
	fwResult := AuditResult{Category: "SECURITY DEFENSES", ControlName: "Windows Defender Firewall Status", Command: "netsh advfirewall set currentprofile state on"}
	if err != nil {
		fwResult.Status = "WARNING"
		fwResult.Result = "Unable to query firewall status via netsh."
		fwResult.Recommendation = "Ensure the WMI service is operational."
		fwResult.Command = ""
	} else if strings.Contains(strings.ToLower(string(outFirewall)), "on") {
		fwResult.Status = "SECURE"
		fwResult.Result = "Active profile firewall is enabled and filtering."
		fwResult.Recommendation = "No action required."
		fwResult.Command = ""
	} else {
		fwResult.Status = "VULNERABLE"
		fwResult.Result = "The active network profile firewall is explicitly DISABLED."
		fwResult.Recommendation = "Execute the remediation command in an elevated prompt."
	}
	audits = append(audits, fwResult)

	// 2. UAC (User Account Control)
	cmdUAC := exec.Command("reg", "query", `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System`, "/v", "EnableLUA")
	cmdUAC.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outUAC, err := cmdUAC.Output()
	uacResult := AuditResult{Category: "SECURITY DEFENSES", ControlName: "User Account Control (UAC)", Command: `reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f`}
	if err != nil {
		uacResult.Status = "WARNING"
		uacResult.Result = "Unable to query Registry for UAC status."
		uacResult.Recommendation = "Verify registry access permissions."
		uacResult.Command = ""
	} else if strings.Contains(string(outUAC), "0x1") {
		uacResult.Status = "SECURE"
		uacResult.Result = "UAC is enabled and enforcing privilege elevation prompts."
		uacResult.Recommendation = "No action required."
		uacResult.Command = ""
	} else {
		uacResult.Status = "VULNERABLE"
		uacResult.Result = "UAC is explicitly DISABLED. Silent privilege escalation is possible."
		uacResult.Recommendation = "Re-enable UAC immediately via Registry."
	}
	audits = append(audits, uacResult)

	// 3. WINDOWS DEFENDER REAL-TIME PROTECTION (NOUVEAU)
	cmdDefender := exec.Command("powershell", "-NoProfile", "-Command", "(Get-MpComputerStatus).RealTimeProtectionEnabled")
	cmdDefender.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outDefender, err := cmdDefender.Output()
	defResult := AuditResult{Category: "SECURITY DEFENSES", ControlName: "Defender Real-Time Protection", Command: `Set-MpPreference -DisableRealtimeMonitoring $false`}
	if err != nil {
		defResult.Status = "WARNING"
		defResult.Result = "Failed to query Defender Engine via PowerShell."
		defResult.Recommendation = "Verify if third-party AV is managing security."
		defResult.Command = ""
	} else if strings.Contains(strings.TrimSpace(string(outDefender)), "True") {
		defResult.Status = "SECURE"
		defResult.Result = "Real-time behavioral monitoring and heuristics are active."
		defResult.Recommendation = "No action required."
		defResult.Command = ""
	} else {
		defResult.Status = "VULNERABLE"
		defResult.Result = "Real-time protection is DISABLED. System exposed to execution of malicious payloads."
		defResult.Recommendation = "Force-enable real-time monitoring via PowerShell (Admin)."
	}
	audits = append(audits, defResult)

	// 4. SMBv1 VULNERABILITY (NOUVEAU)
	cmdSMB := exec.Command("powershell", "-NoProfile", "-Command", "(Get-SmbServerConfiguration).EnableSMB1Protocol")
	cmdSMB.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outSMB, err := cmdSMB.Output()
	smbResult := AuditResult{Category: "NETWORK & SHARING", ControlName: "Legacy SMBv1 Protocol Status", Command: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`}
	if err != nil {
		smbResult.Status = "WARNING"
		smbResult.Result = "Unable to query SMB configuration."
		smbResult.Recommendation = "Requires administrator privileges."
		smbResult.Command = ""
	} else if strings.Contains(strings.TrimSpace(string(outSMB)), "False") {
		smbResult.Status = "SECURE"
		smbResult.Result = "Legacy SMBv1 is disabled (immune to EternalBlue/WannaCry)."
		smbResult.Recommendation = "No action required."
		smbResult.Command = ""
	} else {
		smbResult.Status = "VULNERABLE"
		smbResult.Result = "SMBv1 is ENABLED. Highly vulnerable to lateral movement worms."
		smbResult.Recommendation = "Disable SMBv1 immediately via PowerShell."
	}
	audits = append(audits, smbResult)

	// 5. RDP EXPOSURE (NOUVEAU)
	cmdRDP := exec.Command("reg", "query", `HKLM\System\CurrentControlSet\Control\Terminal Server`, "/v", "fDenyTSConnections")
	cmdRDP.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outRDP, err := cmdRDP.Output()
	rdpResult := AuditResult{Category: "NETWORK & SHARING", ControlName: "Remote Desktop (RDP) Exposure", Command: `reg.exe ADD "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f`}
	if err != nil {
		rdpResult.Status = "WARNING"
		rdpResult.Result = "Cannot read RDP registry keys."
		rdpResult.Recommendation = "Check system policies."
		rdpResult.Command = ""
	} else if strings.Contains(string(outRDP), "0x1") {
		rdpResult.Status = "SECURE"
		rdpResult.Result = "Remote Desktop connections are explicitly denied."
		rdpResult.Recommendation = "No action required. Good attack surface reduction."
		rdpResult.Command = ""
	} else {
		rdpResult.Status = "WARNING"
		rdpResult.Result = "Remote Desktop is ENABLED and accepting incoming connections."
		rdpResult.Recommendation = "If RDP is not strictly required, disable it to prevent brute-force attacks."
	}
	audits = append(audits, rdpResult)

	// 6. PARTAGES RESEAUX
	cmdShare := exec.Command("net", "share")
	cmdShare.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outShare, err := cmdShare.Output()
	shareResult := AuditResult{Category: "NETWORK & SHARING", ControlName: "Active SMB Network Shares", Command: "net share [ShareName] /delete"}
	if err != nil {
		shareResult.Status = "WARNING"
		shareResult.Result = "Unable to verify local network shares allocation."
		shareResult.Recommendation = "Verify if the Server ('LanmanServer') service is active."
		shareResult.Command = ""
	} else {
		shareLines := strings.Split(string(outShare), "\n")
		customShares := 0
		for _, line := range shareLines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Name") || strings.HasPrefix(line, "----") || strings.HasPrefix(line, "The command") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) > 0 {
				shareName := fields[0]
				if !strings.HasSuffix(shareName, "$") && shareName != "Users" && shareName != "Public" {
					customShares++
				}
			}
		}
		if customShares > 0 {
			shareResult.Status = "WARNING"
			shareResult.Result = fmt.Sprintf("%d non-standard network share(s) detected.", customShares)
			shareResult.Recommendation = "Review permissions. Remove unapproved shares."
		} else {
			shareResult.Status = "SECURE"
			shareResult.Result = "No risky custom SMB network shares exposed."
			shareResult.Recommendation = "No action required."
			shareResult.Command = ""
		}
	}
	audits = append(audits, shareResult)

	// 7. COMPTE INVITE (NOUVEAU)
	cmdGuest := exec.Command("powershell", "-NoProfile", "-Command", "(Get-LocalUser -Name Guest).Enabled")
	cmdGuest.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outGuest, err := cmdGuest.Output()
	guestResult := AuditResult{Category: "ACCOUNTS & PRIVILEGES", ControlName: "Guest Account Status", Command: `Disable-LocalUser -Name "Guest"`}
	if err != nil {
		guestResult.Status = "WARNING"
		guestResult.Result = "Failed to query Guest account properties."
		guestResult.Recommendation = "Account may be renamed or missing."
		guestResult.Command = ""
	} else if strings.Contains(strings.TrimSpace(string(outGuest)), "False") {
		guestResult.Status = "SECURE"
		guestResult.Result = "The default Guest account is disabled."
		guestResult.Recommendation = "No action required."
		guestResult.Command = ""
	} else {
		guestResult.Status = "VULNERABLE"
		guestResult.Result = "Guest account is ACTIVE. Allows unauthenticated local access."
		guestResult.Recommendation = "Disable the guest account immediately."
	}
	audits = append(audits, guestResult)

	// 8. ADMINISTRATEURS LOCAUX
	cmdAdmin := exec.Command("net", "localgroup", "administrators")
	cmdAdmin.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outAdmin, err := cmdAdmin.Output()
	adminResult := AuditResult{Category: "ACCOUNTS & PRIVILEGES", ControlName: "Local Administrators Membership", Command: "lusrmgr.msc"}
	if err != nil {
		adminResult.Status = "WARNING"
		adminResult.Result = "Failed to query local administrators security group."
		adminResult.Recommendation = "Ensure account has token privileges."
		adminResult.Command = ""
	} else {
		lines := strings.Split(string(outAdmin), "\n")
		var admins []string
		startParsing := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "----") {
				startParsing = true
				continue
			}
			if strings.HasPrefix(line, "The command") {
				break
			}
			if startParsing && line != "" {
				admins = append(admins, line)
			}
		}
		if len(admins) > 2 {
			adminResult.Status = "WARNING"
			adminResult.Result = fmt.Sprintf("High privilege density: %d admins detected.", len(admins))
			adminResult.Recommendation = "Purge unnecessary accounts via local manager."
		} else {
			adminResult.Status = "SECURE"
			adminResult.Result = "Privilege isolation restricted to authorized accounts."
			adminResult.Recommendation = "No action required."
			adminResult.Command = ""
		}
	}
	audits = append(audits, adminResult)

	return audits
}

func (a *App) ExportAuditReport(results []AuditResult, exportPath string) string {
	if len(results) == 0 {
		return "Aucun résultat d'audit à exporter."
	}
	os.MkdirAll(exportPath, os.ModePerm)
	fileName := filepath.Join(exportPath, fmt.Sprintf("omnitool_audit_%d.html", time.Now().Unix()))

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OmniTool // Local Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', system-ui, sans-serif; background-color: #050506; color: #d1d5db; margin: 0; padding: 40px; }
        h1 { color: #ffffff; border-bottom: 1px solid #1f1f24; padding-bottom: 15px; display: flex; justify-content: space-between; align-items: center; font-size: 1.2rem; letter-spacing: 2px; font-weight: 800; }
        .summary { background-color: #0c0c0e; padding: 25px; border: 1px solid #1f1f24; margin-bottom: 30px; font-family: 'Consolas', monospace; font-size: 0.85rem; }
        .accent-text { color: #00ffcc; }
        table { width: 100%; border-collapse: collapse; margin-top: 25px; background-color: #0c0c0e; border: 1px solid #1f1f24; }
        th, td { padding: 14px 20px; text-align: left; border-bottom: 1px solid #121214; font-family: 'Consolas', monospace; font-size: 0.85rem; vertical-align: top; }
        th { background-color: #050506; color: #52525b; font-size: 0.75rem; letter-spacing: 1px; font-weight: normal; }
        tr:hover { background-color: #121215; }
        .status-SECURE { color: #00ffcc; font-weight: bold; }
        .status-WARNING { color: #f97316; font-weight: bold; }
        .status-VULNERABLE { color: #ef4444; font-weight: bold; }
        .pdf-btn { background-color: transparent; color: #00ffcc; border: 1px solid #00ffcc; padding: 10px 24px; cursor: pointer; font-family: 'Consolas', monospace; font-size: 0.8rem; letter-spacing: 1px; font-weight: bold; }
        .pdf-btn:hover { background-color: #00ffcc; color: #000; }
        .report-footer { margin-top: 50px; border-top: 1px solid #1f1f24; padding-top: 20px; font-family: 'Consolas', monospace; font-size: 0.75rem; color: #52525b; text-align: center; letter-spacing: 1px; }
        .report-footer a { color: #00ffcc; text-decoration: none; }
		code { background-color: #1f1f24; padding: 2px 6px; color: #fff; font-size: 0.75rem;}
        @media print {
            .pdf-btn { display: none !important; }
            body { background-color: white; color: black; padding: 0; }
            h1 { color: black; border-bottom-color: #000; }
            .summary, th { background-color: #f4f4f5; border-color: #e4e4e7; color: black; }
            td { border-color: #e4e4e7; color: black; }
            .status-SECURE { color: #16a34a; }
            .status-WARNING { color: #ea580c; }
            .status-VULNERABLE { color: #dc2626; }
            .report-footer { border-top-color: #e4e4e7; color: #71717a; }
            .report-footer a { color: black; font-weight: bold; }
			code { background-color: #eee; color: #000;}
        }
    </style>
</head>
<body>
    <h1>
        OMNITOOL // LOCAL SECURITY AUDIT REPORT
        <button class="pdf-btn" onclick="window.print()">EXPORT TO PDF</button>
    </h1>
    <div class="summary">
        <p>AUDIT TIMESTAMP: <span class="accent-text">` + time.Now().Format("2006-01-02 15:04:05") + `</span></p>
        <p>SYSTEM ENVIRONMENT: <span class="accent-text">Microsoft Windows host</span></p>
    </div>
    <table>
        <thead><tr><th>CATEGORY</th><th>CONTROL TARGET</th><th>COMPLIANCE STATUS</th><th>FINDINGS / COMPLIANCE RESULT</th><th>REMEDIATION / RECOMMENDATION</th></tr></thead>
        <tbody>`

	for _, r := range results {
		recHtml := r.Recommendation
		if r.Command != "" {
			recHtml += fmt.Sprintf("<br><br><code>%s</code>", r.Command)
		}
		html += fmt.Sprintf(`<tr><td>%s</td><td><strong>%s</strong></td><td><span class="status-%s">%s</span></td><td>%s</td><td>%s</td></tr>`, r.Category, r.ControlName, r.Status, r.Status, r.Result, recHtml)
	}

	html += `</tbody></table>
    <div class="report-footer">
        OmniTool // Open-Source Infrastructure Security Intelligence // GitHub: <a href="https://github.com/ZAERCHER-Loic/OmniTool" target="_blank">github.com/ZAERCHER-Loic/OmniTool</a>
    </div>
</body>
</html>`

	os.WriteFile(fileName, []byte(html), 0644)
	return "Rapport d'audit généré."
}

// --- SCANNER RESEAU ---

func (a *App) GenerateHTMLReport(results []ScanResult, exportPath string) string {
	if len(results) == 0 {
		return "Aucun résultat."
	}
	os.MkdirAll(exportPath, os.ModePerm)
	fileName := filepath.Join(exportPath, fmt.Sprintf("omnitool_report_%d.html", time.Now().Unix()))
	html := `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>OmniTool // Report</title><style>body { font-family: 'Segoe UI', system-ui, sans-serif; background-color: #050506; color: #d1d5db; margin: 0; padding: 40px; }h1 { color: #ffffff; border-bottom: 1px solid #1f1f24; padding-bottom: 15px; display: flex; justify-content: space-between; align-items: center; font-size: 1.2rem; letter-spacing: 2px; font-weight: 800; }.summary { background-color: #0c0c0e; padding: 25px; border: 1px solid #1f1f24; margin-bottom: 30px; font-family: 'Consolas', monospace; font-size: 0.85rem; }.summary p { margin: 6px 0; }.accent-text { color: #00ffcc; }table { width: 100%; border-collapse: collapse; margin-top: 25px; background-color: #0c0c0e; border: 1px solid #1f1f24; }th, td { padding: 14px 20px; text-align: left; border-bottom: 1px solid #121214; font-family: 'Consolas', monospace; font-size: 0.85rem; }th { background-color: #050506; color: #52525b; font-size: 0.75rem; letter-spacing: 1px; font-weight: normal; }tr:hover { background-color: #121215; }.badge { color: #00ffcc; font-weight: bold; }.hostname { color: #52525b; font-size: 0.75rem; display: block; margin-top: 3px; }.mac-text { color: #52525b; font-size: 0.75rem; margin-top: 3px; }.pdf-btn { background-color: transparent; color: #00ffcc; border: 1px solid #00ffcc; padding: 10px 24px; cursor: pointer; font-family: 'Consolas', monospace; font-size: 0.8rem; letter-spacing: 1px; font-weight: bold; }.pdf-btn:hover { background-color: #00ffcc; color: #000; }.report-footer { margin-top: 50px; border-top: 1px solid #1f1f24; padding-top: 20px; font-family: 'Consolas', monospace; font-size: 0.75rem; color: #52525b; text-align: center; letter-spacing: 1px; }.report-footer a { color: #00ffcc; text-decoration: none; }.report-footer a:hover { text-decoration: underline; }@media print { .pdf-btn { display: none !important; } body { background-color: white; color: black; padding: 0; } h1 { color: black; border-bottom-color: #000; } .summary, th { background-color: #f4f4f5; border-color: #e4e4e7; color: black; } td { border-color: #e4e4e7; color: black; } .badge { color: black; } .accent-text { color: black; } .hostname, .mac-text { color: #71717a; } .report-footer { border-top-color: #e4e4e7; color: #71717a; } .report-footer a { color: black; font-weight: bold; } }</style></head><body><h1>OMNITOOL // NETWORK RECONNAISSANCE REPORT<button class="pdf-btn" onclick="window.print()">EXPORT TO PDF</button></h1><div class="summary"><p>TIMESTAMP: <span class="accent-text">` + time.Now().Format("2006-01-02 15:04:05") + `</span></p><p>IDENTIFIED TARGETS: <span class="accent-text">` + strconv.Itoa(len(results)) + `</span></p></div><table><thead><tr><th>TARGET HOST</th><th>PORT</th><th>OPERATING SYSTEM</th><th>HARDWARE INFORMATION / MAC</th><th>SERVICE</th><th>BANNER METADATA</th></tr></thead><tbody>`
	for _, r := range results {
		hostnameStr := ""
		if r.Hostname != "-" {
			hostnameStr = "<span class='hostname'>" + r.Hostname + "</span>"
		}
		html += fmt.Sprintf(`<tr><td><strong>%s</strong>%s</td><td><span class="badge">OPEN // %s</span></td><td>%s</td><td><div>%s</div><div class="mac-text">%s</div></td><td>%s</td><td>%s</td></tr>`, r.IP, hostnameStr, r.Port, r.OS, r.Vendor, r.MAC, r.Service, r.Banner)
	}
	html += `</tbody></table><div class="report-footer">OmniTool // Open-Source Infrastructure Security Intelligence // GitHub: <a href="https://github.com/ZAERCHER-Loic/OmniTool" target="_blank">github.com/ZAERCHER-Loic/OmniTool</a></div></body></html>`
	os.WriteFile(fileName, []byte(html), 0644)
	return "Rapport généré avec succès."
}

func (a *App) ScanNetwork(target string, portsStr string, showInfo bool, usePingSweep bool, timeoutMs int, maxThreads int, exportPath string, autoExportFormat string) []ScanResult {
	a.mu.Lock()
	var scanCtx context.Context
	scanCtx, a.scanCancel = context.WithCancel(a.ctx)
	a.mu.Unlock()
	ipList, err := getIPList(target)
	if err != nil {
		return []ScanResult{}
	}
	portList := parsePorts(portsStr)
	var wg sync.WaitGroup
	resultsChan := make(chan ScanResult, len(ipList)*len(portList))
	semaphore := make(chan struct{}, maxThreads)
	for _, ip := range ipList {
		if scanCtx.Err() != nil {
			break
		}
		isAlive := true
		if usePingSweep && len(ipList) > 1 {
			if !isHostAlive(scanCtx, ip, timeoutMs) {
				isAlive = false
			}
		}
		if isAlive {
			mac, vendor, osName := getHostDetails(ip)
			for _, port := range portList {
				if scanCtx.Err() != nil {
					break
				}
				wg.Add(1)
				semaphore <- struct{}{}
				go a.scanPort(scanCtx, ip, port, showInfo, timeoutMs, mac, vendor, osName, &wg, resultsChan, semaphore)
			}
		}
	}
	wg.Wait()
	close(resultsChan)
	var allResults []ScanResult
	for res := range resultsChan {
		allResults = append(allResults, res)
	}
	if autoExportFormat != "none" && exportPath != "" && len(allResults) > 0 && scanCtx.Err() == nil {
		os.MkdirAll(exportPath, os.ModePerm)
		if autoExportFormat == "csv" || autoExportFormat == "both" {
			fileName := filepath.Join(exportPath, fmt.Sprintf("omnitool_scan_%d.csv", time.Now().Unix()))
			file, err := os.Create(fileName)
			if err == nil {
				defer file.Close()
				writer := csv.NewWriter(file)
				writer.Write([]string{"IP", "Hostname", "Port", "Service", "OS", "MAC", "Constructeur", "Banner"})
				for _, r := range allResults {
					writer.Write([]string{r.IP, r.Hostname, r.Port, r.Service, r.OS, r.MAC, r.Vendor, r.Banner})
				}
				writer.Flush()
			}
		}
		if autoExportFormat == "html" || autoExportFormat == "both" {
			a.GenerateHTMLReport(allResults, exportPath)
		}
	}
	return allResults
}

func getHostDetails(ip string) (string, string, string) {
	mac, vendor, osName := "Inconnu", "Inconnu", "Inconnu"
	cmdPing := exec.Command("ping", "-n", "1", "-w", "400", ip)
	cmdPing.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmdPing.Output(); err == nil {
		if strings.Contains(string(out), "TTL=") {
			parts := strings.Split(string(out), "TTL=")
			if len(parts) > 1 {
				ttl, _ := strconv.Atoi(strings.TrimRight(strings.Fields(parts[1])[0], "\r\n, "))
				if ttl <= 64 {
					osName = "Linux/Android"
				} else if ttl <= 128 {
					osName = "Windows"
				} else {
					osName = "Network Device"
				}
			}
		}
	}
	cmdArp := exec.Command("arp", "-a", ip)
	cmdArp.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmdArp.Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, ip) {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					mac = strings.ReplaceAll(strings.ToUpper(fields[1]), "-", ":")
					if strings.HasPrefix(mac, "00:11:32") {
						vendor = "Synology"
					} else if strings.HasPrefix(mac, "B8:27:EB") || strings.HasPrefix(mac, "DC:A6:32") {
						vendor = "RaspberryPi"
					} else if strings.HasPrefix(mac, "00:50:56") || strings.HasPrefix(mac, "00:0C:29") {
						vendor = "VMware"
					} else if strings.HasPrefix(mac, "00:15:5D") {
						vendor = "Hyper-V"
					} else if strings.HasPrefix(mac, "A4:D1:8C") {
						vendor = "Apple"
					} else {
						vendor = "Generic LAN"
					}
				}
				break
			}
		}
	}
	return mac, vendor, osName
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func getIPList(target string) ([]string, error) {
	if parsedIP := net.ParseIP(target); parsedIP != nil {
		return []string{parsedIP.String()}, nil
	}
	ip, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func parsePorts(portsStr string) []string {
	var finalPorts []string
	for _, part := range strings.Split(portsStr, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) == 2 {
				start, _ := strconv.Atoi(strings.TrimSpace(bounds[0]))
				end, _ := strconv.Atoi(strings.TrimSpace(bounds[1]))
				if start <= end {
					for i := start; i <= end; i++ {
						finalPorts = append(finalPorts, strconv.Itoa(i))
					}
				}
			}
		} else if part != "" {
			finalPorts = append(finalPorts, part)
		}
	}
	return finalPorts
}

func isHostAlive(ctx context.Context, ip string, timeoutMs int) bool {
	probePorts := []string{"80", "443", "445", "3389"}
	alive := false
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, port := range probePorts {
		if ctx.Err() != nil {
			return false
		}
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			var d net.Dialer
			d.Timeout = time.Duration(timeoutMs) * time.Millisecond
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, p))
			if err != nil {
				if strings.Contains(err.Error(), "refused") {
					mu.Lock()
					alive = true
					mu.Unlock()
				}
				return
			}
			if conn != nil {
				conn.Close()
				mu.Lock()
				alive = true
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return alive
}

func (a *App) scanPort(ctx context.Context, ip string, port string, showInfo bool, timeoutMs int, mac string, vendor string, osName string, wg *sync.WaitGroup, results chan<- ScanResult, semaphore chan struct{}) {
	defer wg.Done()
	defer func() { <-semaphore }()
	if ctx.Err() != nil {
		return
	}
	var d net.Dialer
	d.Timeout = time.Duration(timeoutMs) * time.Millisecond
	conn, err := d.DialContext(ctx, "tcp", ip+":"+port)
	if err != nil {
		return
	}
	result := ScanResult{IP: ip, Port: port, Hostname: "-", Service: "-", Banner: "-", MAC: mac, Vendor: vendor, OS: osName}
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		result.Hostname = strings.TrimSuffix(names[0], ".")
	}
	if showInfo {
		if serviceName, exists := knownServices[port]; exists {
			result.Service = serviceName
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buffer := make([]byte, 128)
		if n, err := conn.Read(buffer); err == nil && n > 0 {
			banner := strings.ReplaceAll(strings.ReplaceAll(string(buffer[:n]), "\r", ""), "\n", " ")
			result.Banner = strings.TrimSpace(banner)
		}
	}
	conn.Close()
	runtime.EventsEmit(a.ctx, "port_found", result)
	results <- result
}
