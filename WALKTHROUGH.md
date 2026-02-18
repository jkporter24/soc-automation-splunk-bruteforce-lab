# 📘 Full Walkthrough – SOC Brute Force Detection & Automation Lab

In this lab, I built an isolated attacker ↔ victim environment to simulate an SMB brute-force attack, detect it in Splunk, and automate SOC case documentation using Python.

This walkthrough explains exactly what I installed, configured, and built.

---

# 🧱 Phase 1 – Environment Setup

## 🎯 Objective
Create a controlled lab environment to simulate brute-force authentication attacks and generate real Windows Security logs.

## 🔧 What I Installed

- Kali Linux (Attacker VM)
- Windows 10 (Victim VM)
- Splunk Enterprise (Installed on Windows 10)
- Python (for automation scripting)
- VirtualBox (host-only network configuration)

---

## 🖥 Network Configuration

I configured both virtual machines using a Host-Only Adapter to isolate traffic from the internet.

### Windows Configuration:
- Static IP: `10.10.10.10`

![Windows Static IP](./screenshots/01_windows_static_ip.PNG)

This allowed me to:
- Control traffic flow
- Eliminate external noise
- Generate clean authentication telemetry

---

## 🐉 Kali Configuration

I validated connectivity from Kali to Windows before launching any attack:

```bash
ping -c 4 10.10.10.10
```

![Ping Validation](./screenshots/02_kali_ping_success.PNG)

This confirmed internal network communication was working properly.

---

# ⚔ Phase 2 – Attack Simulation

## 🎯 Objective
Generate real Windows Event ID 4625 (Failed Logon) entries.

From Kali, I executed an SMB brute-force simulation:

```bash
for i in {1..15}; do smbclient -L //10.10.10.10 -U vboxuser%wrongpass; done
```

Results:
- NT_STATUS_LOGON_FAILURE responses
- Account lockout triggered
- Windows Security Event 4625 logs generated

![SMB Brute Force](./screenshots/03_kali_smb_bruteforce.PNG)

This created authentic authentication telemetry for detection testing.

---

# 📊 Phase 3 – Log Validation in Splunk

After generating attack traffic, I verified log ingestion in Splunk.

## 🔎 Aggregating Failed Logons

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Source_Network_Address, Account_Name
| sort - count
```

This confirmed:
- Attacker IP: `10.10.10.20`
- Target Account: `vboxuser`
- High volume of failed logins

![4625 Aggregation](./screenshots/04_splunk_4625_aggregation.PNG)

---

## 📈 Event Distribution Analysis

To validate overall authentication activity:

```spl
index=main sourcetype="WinEventLog:Security"
| stats count by EventCode
```

Key Events Observed:
- 4624 – Successful Logon
- 4625 – Failed Logon

![Event Distribution](./screenshots/06_splunk_eventcode_distribution.PNG)

---

# 🚨 Phase 4 – Detection Engineering

## 🎯 Objective
Engineer a threshold-based brute force detection rule.

I built the following SPL query:

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| where NOT (Source_Network_Address="127.0.0.1" OR Source_Network_Address="::1")
| bucket _time span=5m
| stats count as failed_logins by Account_Name, Source_Network_Address, _time
| where failed_logins >= 10
| eval severity="High"
| table _time Account_Name Source_Network_Address failed_logins severity
```

Detection Logic:
- Buckets events into 5-minute intervals
- Flags ≥10 failed attempts
- Excludes local system traffic
- Assigns severity

![Threshold Detection](./screenshots/05_splunk_threshold_detection.PNG)

This simulates real SOC detection engineering practices.

---

# 🤖 Phase 5 – SOC Automation

## 🎯 Objective
Automate incident documentation using Splunk REST API + Python.

I wrote a Python script that:
- Authenticates to Splunk REST API (Port 8089)
- Queries detection results
- Generates a structured case note in Markdown format

Execution:

```bash
python soc_case_automation.py
```

![Python Script Execution](./screenshots/07_python_script_execution.PNG)

---

## 📝 Generated Case Output

The script automatically generates:

- Source IP
- Target account
- Failed login count
- Severity rating
- Recommended response steps

![Generated Case Note](./screenshots/08_generated_case_note.PNG)

This simulates a Tier 1 SOC documentation workflow.

---

# 🧠 What I Demonstrated in This Lab

- Virtual lab network design
- SMB brute-force simulation
- Windows Security Event analysis (4625)
- SPL detection engineering
- Threshold-based alert logic
- REST API integration
- Python automation
- SOC case documentation workflow

---

# 🎯 Why This Project Matters

In this project, I:

- Built the lab infrastructure
- Simulated adversary behavior
- Engineered detection logic
- Validated telemetry
- Automated SOC triage

This demonstrates hands-on detection engineering and security automation capability beyond basic log analysis.
