<p align="center">
  <img src="https://github.com/user-attachments/assets/a46954f5-9126-42c7-b21a-3a0b11827406" width="800"/>
</p>

# 🛡️ LANSec — Intelligent IDS/IPS for Local Networks

**LANSec** is a high-performance **Intrusion Detection and Prevention System (IDPS)** designed to monitor and protect local networks in real time.

The system combines **signature-based detection**, **statistical anomaly detection**, and **automatic firewall mitigation** to detect and stop network attacks across multiple OSI layers.

Built for cybersecurity research, educational purposes, and defensive monitoring of home or small networks.

---

# 🚀 Features

### 📡 Real-Time Network Monitoring
Packet sniffing powered by **Scapy** enables deep packet inspection (DPI) and protocol analysis directly from LAN traffic.

### 🧠 Intelligent Anomaly Detection
Statistical detection using:

- **Exponential Moving Average (EMA)**
- **Z-Score analysis**

This allows the system to learn normal traffic behavior and detect **abnormal spikes such as zero-day floods**.

### 🔥 Automatic Attack Mitigation
Detected attackers can be blocked instantly using dynamic firewall rules via **iptables**.

### 🖥️ Web Dashboard
A real-time monitoring dashboard built with **Flask** that displays:

- Live attack alerts
- Device statistics
- Network events
- Historical logs

### 🛡️ Multi-Layer Attack Detection

#### Layer 2
- ARP Spoofing
- ARP Sweep
- MAC Randomization

#### Layer 3 / 4
- SYN Flood
- UDP Flood
- ICMP Flood
- TCP SYN Scan
- TCP Connection Scan
- Ping Sweep
- SSH Brute Force

#### Layer 7 (Application Layer)
Normalized HTTP inspection for:

- SQL Injection
- Cross-Site Scripting (XSS)
- Directory Traversal

---

# 📊 Architecture

LANSec uses a **modular detection pipeline** that separates traffic collection, preprocessing, detection, and prevention.

```
        Network Traffic
              │
              ▼
        Sniffer Engine
         (Scapy DPI)
              │
              ▼
         Normalization
        (HTTP Parsing)
              │
              ▼
           Detectors
   ├─ Network Attacks
   ├─ Web Attacks
   └─ Anomaly Engine
              │
              ▼
          Logger / Alerts
              │
              ▼
          Prevention
       (iptables blocking)
              │
              ▼
            Web UI
```

The modular architecture allows easy addition of new detectors and analysis modules without modifying the core system.

---

# 🖥️ Dashboard

The system includes a **Flask-based Web UI** that provides real-time visualization of network security events.

Features include:

- Real-time attack alerts
- Visualization of detected attacks
- Device statistics
- Historical event logs
- Network monitoring interface

*(Add a screenshot here if available)*

Example:

```
/screenshots/dashboard.png
```

---

# 🛠️ Installation

## Requirements

- Linux (recommended: Ubuntu / Kali Linux)
- Python 3.10+
- Root privileges
- `iptables` enabled

---

## Clone the Repository

```bash
git clone https://github.com/IdodiDuck/LANSec.git
cd LANSec
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Run the System

```bash
sudo python main.py
```

Root privileges are required for packet sniffing and firewall rule manipulation.

---

# ⚙️ Project Structure

```
LANSec/
│
├── events.py
├── main.py
│
├── testing/
│   ├── anomaly_generator.py
│   ├── arp_spoof.py
│   ├── arp_sweep.py
│   ├── icmp_flood.py
│   ├── ping_sweep.py
│   ├── ssh_bf.py
│   ├── ssh_passwords.txt
│   ├── syn_flood.py
│   ├── syn_scan.py
│   └── udp_flood.py
│
├── configuration/
│   ├── config.py
│   ├── connect_to_lan.sh
│   └── init_lansec.sh
│
├── detect/
│   ├── anomaly_detector.py
│   ├── arp_spoof.py
│   ├── arp_sweep.py
│   ├── base_detector.py
│   ├── data_aggregator.py
│   ├── dir_traversal.py
│   ├── icmp_flood.py
│   ├── ping_sweep.py
│   ├── randomized_mac.py
│   ├── rate_limiter.py
│   ├── sqli.py
│   ├── ssh_bruteforce.py
│   ├── syn_flood.py
│   ├── syn_scan.py
│   ├── udp_flood.py
│   └── xss.py
│
├── prevent/
│   └── iptbls.py
│
├── utils/
│   ├── address.py
│   ├── alert.py
│   ├── http_normalizer.py
│   └── logger.py
│
├── web/
│   ├── app.py
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   └── js/
│   │       └── dashboard.js
│   └── templates/
│       └── index.html
│
└── .gitignore
```

The modular structure separates detection engines, testing tools, utilities, prevention mechanisms, and UI components.

---

# 🔬 Detection Methods

LANSec combines multiple detection techniques.

### Signature-Based Detection

Pattern matching against known attack signatures for detecting application attacks such as:

- SQL Injection
- XSS
- Directory Traversal

### Behavioral Detection

Statistical analysis of network behavior to detect abnormal traffic patterns using:

- Exponential Moving Average
- Z-Score anomaly scoring

### Flood Detection

Traffic rate analysis is used to detect network-based denial-of-service attacks including:

- SYN Flood
- UDP Flood
- ICMP Flood

---

# 🧪 Attack Testing Tools

The project includes a **testing suite** that allows simulation of attacks in a controlled environment.

Available attack generators:

- ARP Spoofing
- ARP Sweep
- Ping Sweep
- SYN Scan
- SYN Flood
- UDP Flood
- ICMP Flood
- SSH Brute Force
- Anomaly traffic generator

These tools help validate detection accuracy and reduce false positives.

---

# 📚 Educational Purpose

This project was developed as part of a **cybersecurity research / educational project** focused on building an **intrusion detection and prevention system for local networks**.

The goal is to demonstrate how modern IDS/IPS systems combine multiple techniques including:

- Signature-based detection
- Behavioral analysis
- Statistical anomaly detection
- Automated mitigation

---

# ⚠️ Disclaimer

This tool is intended for **educational and defensive security purposes only**.

Do **not** deploy or use this tool on networks without proper authorization.

The authors are not responsible for misuse of this software.

---

# 👨‍💻 Authors

Developed by:

**Ido**  
**Tal**

---

# ⭐ Future Improvements

Possible future improvements include:

- Machine learning based anomaly detection
- Threat intelligence integration
- Improved attack correlation
- Distributed network monitoring
- Advanced visualization in the web dashboard
