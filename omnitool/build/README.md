# OmniTool

> High-performance network reconnaissance and infrastructure auditing toolkit built with **Go**, **React**, **TypeScript**, and **Wails**.

![Go](https://img.shields.io/badge/Go-1.18+-00ADD8?logo=go)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript)
![Wails](https://img.shields.io/badge/Wails-v2-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)

---

## Overview

OmniTool is a desktop application designed for network discovery, infrastructure auditing, and asset visibility.

The project combines the execution performance of Go with a modern React/TypeScript interface to provide fast and intuitive network reconnaissance capabilities. Through a lightweight desktop architecture powered by Wails, OmniTool delivers native performance without the overhead traditionally associated with Electron-based applications.

The application is intended for system administrators, IT engineers, cybersecurity professionals, homelab operators, and network enthusiasts who require rapid visibility into local infrastructure.

---

## Features

### Host Discovery

Quickly identify active hosts within a target subnet using concurrent network probes.

**Capabilities**

* CIDR subnet scanning
* Active host detection
* Fast discovery workflow
* Parallelized connection handling

---

### Multi-Threaded Scan Engine

The scanning engine is built around Go's concurrency model, enabling efficient processing of large address ranges.

**Highlights**

* Goroutine-based execution
* Semaphore-controlled concurrency
* Configurable thread pools
* Optimized resource utilization

---

### Real-Time Results Streaming

Results are displayed as they are discovered rather than waiting for the scan to complete.

**Benefits**

* Immediate visibility
* Improved user experience
* Faster investigation workflows
* Continuous UI updates

---

### Operating System Detection

OmniTool performs lightweight operating system estimation using network response characteristics.

**Supported Detection Categories**

* Windows
* Linux
* Android
* Network Appliances
* Unknown Devices

---

### Hardware Vendor Identification

The application extracts MAC addresses from local network information and correlates them with known vendor databases.

Examples include:

* Apple
* Synology
* VMware
* Raspberry Pi
* Cisco
* Ubiquiti
* Intel

This provides additional context when identifying devices on a network.

---

### Scan Profiles

Choose a scanning strategy depending on operational requirements.

| Profile    | Description                               |
| ---------- | ----------------------------------------- |
| Stealth    | Reduced activity and slower execution     |
| Normal     | Balanced performance and accuracy         |
| Aggressive | Maximum concurrency for rapid assessments |

---

### Audit History

All completed scans can be stored locally for future analysis.

Features include:

* Historical scan review
* Result management
* Data cleanup tools
* Export functionality

---

### Report Generation

Generate audit-ready reports from collected scan data.

Supported formats:

* CSV
* HTML

HTML reports are designed to be printable and compatible with PDF export workflows.

---

### Modern Desktop Interface

OmniTool uses a custom frameless desktop interface built with React.

Interface features include:

* Borderless window mode
* Custom title bar
* Dynamic accent colors
* Responsive layouts
* Native desktop integration

---

## Architecture

OmniTool follows a hybrid architecture that separates networking operations from presentation logic.

```text
┌──────────────────────────────┐
│      React + TypeScript      │
│            UI Layer          │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│           Wails v2           │
│      Native Application      │
│          Bridge Layer        │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│             Go               │
│       Scan Engine Core       │
└──────────────────────────────┘
```

---

## Technology Stack

| Layer             | Technology |
| ----------------- | ---------- |
| Backend           | Go         |
| Frontend          | React      |
| Language          | TypeScript |
| Desktop Framework | Wails      |
| Build Tool        | Vite       |
| Package Manager   | npm        |

---

## Requirements

### Backend

* Go 1.18 or newer
* Windows environment
* Standard networking utilities available

### Frontend

* Node.js 18+
* npm

### Wails

Install Wails CLI:

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@latest
```

Verify installation:

```bash
wails doctor
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Akune122/OmniTool.git
cd omnitool
```

Synchronize dependencies:

```bash
go mod tidy
```

Install frontend packages:

```bash
npm install
```

---

## Development

Run the application in development mode with live reload enabled:

```bash
wails dev
```

Changes made to either Go or React source files will automatically trigger recompilation.

---

## Production Build

Generate a standalone executable:

```bash
wails build -clean
```

The generated binary will be available inside:

```text
build/bin/
```

---

## Project Structure

```text
OmniTool/
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── build/
│
├── app.go
├── main.go
├── go.mod
├── go.sum
├── wails.json
│
└── README.md
```

---

## Roadmap

Planned improvements include:

* Service banner detection
* Extended port profiling
* Advanced filtering system
* Search and tagging capabilities
* Enhanced reporting engine
* Cross-platform support
* Plugin architecture

---

## Security Notice

OmniTool is intended exclusively for authorized network administration, infrastructure auditing, educational purposes, and cybersecurity research.

Users are responsible for ensuring that all scans are performed only against systems and networks for which they have explicit authorization.

Unauthorized scanning may violate local laws, regulations, or organizational policies.

---

