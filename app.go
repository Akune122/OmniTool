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

func (a *App) GenerateHTMLReport(results []ScanResult, exportPath string) string {
	if len(results) == 0 {
		return "Aucun résultat."
	}
	os.MkdirAll(exportPath, os.ModePerm)
	fileName := filepath.Join(exportPath, fmt.Sprintf("omnitool_report_%d.html", time.Now().Unix()))

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OmniTool // Report</title>
    <style>
        body { font-family: 'Segoe UI', system-ui, sans-serif; background-color: #050506; color: #d1d5db; margin: 0; padding: 40px; }
        h1 { color: #ffffff; border-bottom: 1px solid #1f1f24; padding-bottom: 15px; display: flex; justify-content: space-between; align-items: center; font-size: 1.2rem; letter-spacing: 2px; font-weight: 800; }
        .summary { background-color: #0c0c0e; padding: 25px; border: 1px solid #1f1f24; margin-bottom: 30px; font-family: 'Consolas', monospace; font-size: 0.85rem; }
        .summary p { margin: 6px 0; }
        .accent-text { color: #00ffcc; }
        table { width: 100%; border-collapse: collapse; margin-top: 25px; background-color: #0c0c0e; border: 1px solid #1f1f24; }
        th, td { padding: 14px 20px; text-align: left; border-bottom: 1px solid #121214; font-family: 'Consolas', monospace; font-size: 0.85rem; }
        th { background-color: #050506; color: #52525b; font-size: 0.75rem; letter-spacing: 1px; font-weight: normal; }
        tr:hover { background-color: #121215; }
        .badge { color: #00ffcc; font-weight: bold; }
        .hostname { color: #52525b; font-size: 0.75rem; display: block; margin-top: 3px; }
        .mac-text { color: #52525b; font-size: 0.75rem; margin-top: 3px; }
        .pdf-btn { background-color: transparent; color: #00ffcc; border: 1px solid #00ffcc; padding: 10px 24px; cursor: pointer; font-family: 'Consolas', monospace; font-size: 0.8rem; letter-spacing: 1px; font-weight: bold; }
        .pdf-btn:hover { background-color: #00ffcc; color: #000; }
        
        /* Style du nouveau Footer */
        .report-footer { margin-top: 50px; border-top: 1px solid #1f1f24; padding-top: 20px; font-family: 'Consolas', monospace; font-size: 0.75rem; color: #52525b; text-align: center; letter-spacing: 1px; }
        .report-footer a { color: #00ffcc; text-decoration: none; }
        .report-footer a:hover { text-decoration: underline; }

        @media print {
            .pdf-btn { display: none !important; }
            body { background-color: white; color: black; padding: 0; }
            h1 { color: black; border-bottom-color: #000; }
            .summary, th { background-color: #f4f4f5; border-color: #e4e4e7; color: black; }
            td { border-color: #e4e4e7; color: black; }
            .badge { color: black; }
            .accent-text { color: black; }
            .hostname, .mac-text { color: #71717a; }
            .report-footer { border-top-color: #e4e4e7; color: #71717a; }
            .report-footer a { color: black; font-weight: bold; }
        }
    </style>
</head>
<body>
    <h1>
        OMNITOOL // NETWORK RECONNAISSANCE REPORT
        <button class="pdf-btn" onclick="window.print()">EXPORT TO PDF</button>
    </h1>
    <div class="summary">
        <p>TIMESTAMP: <span class="accent-text">` + time.Now().Format("2006-01-02 15:04:05") + `</span></p>
        <p>IDENTIFIED TARGETS: <span class="accent-text">` + strconv.Itoa(len(results)) + `</span></p>
    </div>
    <table>
        <thead><tr><th>TARGET HOST</th><th>PORT</th><th>OPERATING SYSTEM</th><th>HARDWARE INFORMATION / MAC</th><th>SERVICE</th><th>BANNER METADATA</th></tr></thead>
        <tbody>`

	for _, r := range results {
		hostnameStr := ""
		if r.Hostname != "-" {
			hostnameStr = "<span class='hostname'>" + r.Hostname + "</span>"
		}
		html += fmt.Sprintf(`<tr><td><strong>%s</strong>%s</td><td><span class="badge">OPEN // %s</span></td><td>%s</td><td><div>%s</div><div class="mac-text">%s</div></td><td>%s</td><td>%s</td></tr>`, r.IP, hostnameStr, r.Port, r.OS, r.Vendor, r.MAC, r.Service, r.Banner)
	}

	html += `</tbody></table>
    <div class="report-footer">
        OmniTool // Open-Source Infrastructure Security Intelligence // GitHub: <a href="https://github.com/Akune122/OmniTool" target="_blank">github.com/ZAERCHER-Loic/OmniTool</a>
    </div>
</body>
</html>`

	os.WriteFile(fileName, []byte(html), 0644)
	return "Rapport généré avec succès."
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
