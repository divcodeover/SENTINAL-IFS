# SentinelFS — Client-Side Static Malware Triage & Cryptographic Forensics Workstation

[![React](https://img.shields.io/badge/React-19-blue.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-6.x-646CFF.svg)](https://vite.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-v4-38B2AC.svg)](https://tailwindcss.com/)
[![Zero Execution](https://img.shields.io/badge/Architecture-Zero--Execution-10B981.svg)](#how-the-file-analyzer-works)

> **"Inspecting suspicious artifacts at the byte level without ever running the risk of executing them."**

---

## 📌 Project Overview

**SentinelFS** is a browser-based, zero-installation static malware triage and cryptographic forensics workstation engineered for Security Operations Center (SOC) analysts, incident responders, and computer science researchers.

In traditional incident response, first-hop triage of unknown email attachments, binaries, or scripts carries two major risks:
1. **Accidental Host Execution:** Inspecting files on a desktop environment risks accidentally invoking operating system shell handlers or executable loaders.
2. **Operational Security (OpSec) Leaks:** Uploading proprietary or targeted enterprise binaries to public multi-engine cloud sandboxes (such as VirusTotal) exposes sensitive internal data to external feeds.

SentinelFS eliminates both risks through a **Zero-Execution Client-Side Architecture**. Files dropped into the workstation are intercepted in the browser DOM and parsed purely as inert `ArrayBuffer` and `Uint8Array` memory streams. No file is ever executed by the host operating system, and no byte ever leaves the local machine over the network.

### Core Capabilities
* **🛡️ Zero-Execution File Ingestion:** Drag-and-drop or manual file staging directly into isolated browser memory buffers.
* **📊 Mathematical Shannon Entropy ($H$) Analysis:** Computes byte randomness on a $0.000$ to $8.000$ bit scale across a 256-bucket histogram to detect UPX packing, crypters, and encrypted ransomware payloads.
* **🔐 Hardware-Accelerated Cryptographic Digests:** Generates **SHA-256**, **SHA-1**, and **MD5** Indicators of Compromise (IOCs) instantaneously using the native Web Crypto API.
* **🧬 Magic Byte & Signature Verification:** Inspects leading hexadecimal headers (`4D 5A` for PE, `50 4B 03 04` for ZIP/OOXML, `25 50 44 46` for PDF) to catch spoofed file extensions.
* **🔍 Interactive 16-Byte Hex Dump:** Low-level memory offset viewer with live hexadecimal-to-ASCII translation and search filtering.
* **⚡ Heuristic String Extraction Engine:** Scans binary streams for printable ASCII sequences and flags suspicious Windows API calls (`VirtualAlloc`, `WriteProcessMemory`), obfuscated shells (`powershell.exe -enc`), and registry persistence keys (`CurrentVersion\Run`).
* **⚖️ Binary Differential Analysis (Diff Tool):** Side-by-side comparison of two artifacts to evaluate byte-size deltas, hash parity, and entropy shifts.
* **📋 SIEM-Ready Audit Reports:** Exports machine-readable JSON IOC manifests, CSV artifact ledgers, and printable executive summaries.
* **🎓 Built-In Presentation Tour Mode:** Interactive 6-step guided walkthrough with live UI state transitions and presenter talking points.

---

## 🛠️ Tech Stack

| Layer | Technology | Role & Engineering Justification |
| :--- | :--- | :--- |
| **UI Library** | **React 19** | Declarative, component-driven state management enabling instantaneous updates across the hex viewer, entropy charts, and inspector drawer without DOM lag. |
| **Build Tool & Bundler** | **Vite** | Lightning-fast ES-module development server and optimized production asset bundling. |
| **Styling Framework** | **Tailwind CSS** | High-density, utility-first styling system with semantic threat color-coding and responsive workspace layouts. |
| **Language** | **TypeScript** | Enforces strict compile-time type safety across binary buffers, memory offsets, hash records, and forensic telemetry models. |
| **Cryptographic Engine** | **Web Crypto API (`crypto.subtle`)** | Browser-native, hardware-accelerated asynchronous SHA-256 and SHA-1 computation on raw `ArrayBuffer` streams. |
| **Iconography** | **Lucide React** | Clean, consistent cybersecurity and forensic interface iconography. |

---

## 🚀 Installation & Local Setup Instructions

### Prerequisites
* **Node.js** (v18.0.0 or higher recommended)
* **npm** (included with Node.js)

### Step-by-Step Setup

1. **Clone the Repository (or Extract the Project Archive):**
   ```bash
   git clone https://github.com/<your-username>/sentinel-file-inspector.git
   cd sentinel-file-inspector
   ```

2. **Install Dependencies:**
   ```bash
   npm install --legacy-peer-deps
   ```

3. **Start the Development Server:**
   ```bash
   npm run dev
   ```

4. **Launch in Browser:**
   Open **[http://localhost:3000](http://localhost:3000)** in Chrome, Edge, Brave, or Firefox.

5. **Build for Production (Optional):**
   ```bash
   npm run build
   npm run preview
   ```

---

## 🔬 How the File Analyzer Works

The forensic engine (`src/utils/fileAnalyzer.ts`) processes every ingested file through a five-stage deterministic pipeline in browser RAM:

### 1. Memory Decoupling via `FileReader`
When a user drops a file into the interface, the browser captures the `File` reference and invokes `FileReader.readAsArrayBuffer()`. The file contents are cast into an `ArrayBuffer` and wrapped in a `Uint8Array` view. Because the OS shell (`explorer.exe`, `cmd.exe`, or `execve`) is never invoked, binary execution is impossible.

### 2. Cryptographic Fingerprinting
The raw `ArrayBuffer` is passed into `window.crypto.subtle.digest()` to compute **SHA-256** and **SHA-1** digests asynchronously on the client CPU, while a fast RFC 1321 buffer routine computes the **MD5** checksum. Each byte of the digest is formatted as a two-character zero-padded hexadecimal string.

### 3. Single-Pass 256-Bucket Shannon Entropy ($H$)
To evaluate whether a binary is packed or encrypted, the analyzer allocates a 256-slot frequency array (`Uint32Array(256)`) and counts the occurrence of every byte value (`0x00` to `0xFF`) in a single $O(N)$ pass. It then applies Claude Shannon's information theory formula:

$$H(X) = - \sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$

* **$0.00 - 4.50\text{ bits/byte}$:** Low randomness — plain text, logs, or uncompiled source code.
* **$4.50 - 6.80\text{ bits/byte}$:** Moderate randomness — standard unpacked executables and compiled binaries.
* **$7.20 - 8.00\text{ bits/byte}$:** Maximal randomness — compressed archives, UPX-packed malware, or encrypted ransomware payloads. SentinelFS automatically elevates executables with $H > 7.20$ to **Critical** status.

### 4. Magic Number & Extension Spoofing Detection
The analyzer slices the first 4 to 16 bytes of the `Uint8Array` and compares the hexadecimal sequence against known file signatures:
* `4D 5A` (`MZ`) $\rightarrow$ Windows Portable Executable (`.exe`, `.dll`)
* `50 4B 03 04` (`PK..`) $\rightarrow$ ZIP Archive / Office Open XML (`.zip`, `.docx`, `.xlsx`)
* `25 50 44 46` (`%PDF`) $\rightarrow$ Adobe PDF Document
* `7F 45 4C 46` (`.ELF`) $\rightarrow$ Linux Executable and Linkable Format

If an artifact is named `invoice.pdf` but begins with `4D 5A`, SentinelFS flags a high-severity masquerading alert.

### 5. 16-Byte Hex Dump & Heuristic Regex Scanner
The analyzer formats the raw byte stream into 16-byte aligned memory rows with an 8-digit hex offset, 16 hex byte pairs, and a 16-character printable ASCII column (replacing non-printable control characters outside ASCII `32–126` with `.`). Concurrently, it extracts contiguous ASCII strings ($\ge 4$ characters) and evaluates them against heuristic signatures for:
* **Process Injection & Hollowing:** `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `LoadLibraryA`
* **Obfuscated Command Execution:** `powershell.exe -enc`, `cmd.exe /c`, `WScript.Shell`
* **Persistence Hooks:** `CurrentVersion\Run`, `HKEY_LOCAL_MACHINE`, `SchTasks`
* **Network Callbacks:** Embedded IPv4 addresses and HTTP/HTTPS C2 endpoints

---

## 🎯 How to Present This as a Portfolio Project

SentinelFS is designed to stand out in technical interviews, academic capstone defenses, and cybersecurity portfolio reviews.

### 1. Use the Built-In Presentation Tour
Click the **"Presentation Tour"** button in the top navigation bar (or left sidebar) to launch an interactive 6-step guided overlay:
* **Step 1 (Telemetry Dashboard):** Highlight instant situational awareness across total staged artifacts, flagged threats, and quarantined items.
* **Step 2 (Zero-Execution Ingestion):** Drag any file from your desktop onto the browser window to demonstrate real-time client-side byte ingestion.
* **Step 3 (Forensic Explorer & Batch IOCs):** Select multiple artifacts to trigger the purple Batch Action Bar and copy all SHA-256 hashes in one click.
* **Step 4 (Deep-Dive Inspector):** Click `invoice_malware.exe` to showcase its **7.82 entropy score** and explain how math exposes packed malware without executing it.
* **Step 5 (Hex Dump & String Heuristics):** Scroll to the 16-byte Hex Viewer and point out flagged strings like `VirtualAlloc` and `powershell.exe -enc`.
* **Step 6 (Binary Diff & SIEM Report):** Open the **Compare Files** modal and the **Audit Report Generator** to export a JSON IOC manifest.

### 2. Key Talking Points for Recruiters & Evaluators
* **Real Math & Native Browser APIs:** Emphasize that the app does not rely on heavy external libraries for its core logic—entropy histograms, hex memory alignment, and `crypto.subtle` SHA-256 hashing are implemented directly on typed arrays (`Uint8Array`).
* **Privacy-First Zero-Trust Design:** Highlight why enterprises need local browser-based triage tools: zero cloud upload latency, zero third-party data leakage, and zero risk of host infection.
* **Classroom & Lab Readiness:** Explain how universities can use SentinelFS to let students safely inspect malware structures on standard lab PCs without provisioning complex virtual machines.

---

## 👩‍💻 Developer Credits & Internship Attribution

This project was designed, engineered, and documented as part of an industrial cybersecurity internship:

* **Developer:** **Divya Mohanty**
* **University System ID:** `2023305077`
* **Academic Institution:** Department of Computer Science & Engineering, School of Computer Science & Engineering, **Sharda University**, Greater Noida
* **Role:** Cybersecurity Intern
* **Host Organization:** **Net2Secure Private Limited**
* **Organization Address:**  
  Office No- TS-933, Galaxy Blue Sapphire, 9th Floor,  
  Sector-4, Greater Noida, Gautam Buddha Nagar, Noida,  
  Uttar Pradesh, India – 201305

---

## 📄 License

This project is available under the **MIT License** for academic, research, and defensive cybersecurity use.
