# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with an onion and crosshair"/>

# Threat Hunt Report: Unauthorized TOR Usage

This project documents an end-to-end threat hunting scenario conducted within the Cyber Range environment. The objective of this exercise was to simulate unauthorized TOR browser usage on an endpoint and to perform a full threat hunting investigation using Microsoft Defender for Endpoint (MDE).

The project is divided into two parts:

**Part 1 – Scenario Creation**
A simulated bad actor performs suspicious and policy-violating activity on the network. All actions are intentionally executed to generate endpoint telemetry that is collected and logged by Microsoft Defender for Endpoint.

**Part 2 – Threat Hunting & Analysis**
A threat hunting operation is conducted in response to the simulated activity from Part 1. Endpoint telemetry is analyzed to identify indicators of compromise (IoCs), reconstruct the attacker’s activity, and produce a formal threat hunt report.

---

# Part 1 – Scenario Creation

The following document outlines the threat event design and execution used to generate the TOR-related activity observed during this investigation:

**[Threat Event: Unauthorized TOR Usage – Scenario Creation](https://github.com/awl4114awl/lognpacific-public/blob/main/cyber-range/threat-hunting-scenarios/_template_threat_event%28TOR%20Usage%29.md)**

### Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

### Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

# Part 2 - Threat Hunting & Analysis

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

### Steps Taken

#### 1. Searched the `DeviceFileEvents` Table

The `DeviceFileEvents` table was queried to identify file activity related to TOR usage on the endpoint `threat-hunt-lab`. The search focused on file names containing the string “tor” as well as a file named `tor-shopping-list.txt`, which was deliberately created during the threat simulation.

The results showed TOR-related files being written to disk following execution of the TOR Browser portable installer, including the extraction of TOR Browser components to the user’s desktop. Additionally, a file named `tor-shopping-list.txt` was created on the desktop by the user `awl4114awl`, indicating potential documentation of TOR-related activity.

These file events confirmed both the presence of TOR Browser artifacts on the system and user interaction consistent with unauthorized TOR usage.
Query used to locate events:

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "awl4114awl"
| where FileName has_any ("tor", "tor-shopping-list.txt")
| order by Timestamp asc
| project Timestamp, ActionType, FileName, FolderPath, SHA256
```

<p align="left">
  <img src="screenshots/Screenshot 2026-01-09 072507.png" width="750">
</p>

---

#### 2. Searched the `DeviceProcessEvents` Table

The `DeviceProcessEvents` table was queried to identify execution of the TOR Browser portable installer. The search focused on process command lines containing the TOR installer filename.

The results showed that the user `awl4114awl` executed the TOR Browser portable installer from the Downloads directory using a silent installation switch. This behavior is notable because silent installs bypass standard user prompts and can be indicative of attempts to install software covertly.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where AccountName == "awl4114awl"
| where ProcessCommandLine has "tor-browser-windows-x86_64-portable"
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ProcessCommandLine, SHA256
```

<p align="left">
  <img src="screenshots/Screenshot 2026-01-09 072720.png" width="750">
</p>

---

#### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Additional queries of the DeviceProcessEvents table were performed to identify execution of TOR Browser components following installation. The search targeted known TOR-related executables, including firefox.exe and tor.exe.

The results confirmed that TOR Browser was successfully launched by the user `awl4114awl`, with multiple TOR-related processes spawned during the session. This activity indicates active usage of TOR Browser rather than a dormant or incomplete installation.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where AccountName == "awl4114awl"
| where FileName has_any ("tor.exe", "firefox.exe")
| order by Timestamp asc
| project Timestamp, FileName, FolderPath, ProcessCommandLine, SHA256
```

<p align="left">
  <img src="screenshots/Screenshot 2026-01-09 074152.png" width="750">
</p>

---

#### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

The `DeviceNetworkEvents` table was queried to identify outbound network connections initiated by TOR Browser processes. The investigation focused on connections associated with `tor.exe` and `firefox.exe`, including traffic over ports commonly used by the TOR network.

The results showed multiple outbound connections initiated by TOR-related processes, including connections to external IP addresses and local loopback communication. These findings confirm that TOR Browser successfully established network connectivity and was actively used for browsing activity.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "awl4114awl"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| order by Timestamp asc
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```

<p align="left">
  <img src="screenshots/Screenshot 2026-01-09 074928.png" width="750">
</p>

---

## Chronological Event Timeline

### 1. File Download – TOR Browser Installer

**Timestamp:**
January 9, 2026 – 06:20:20 AM

**Event:**
The user `awl4114awl` downloaded a TOR Browser portable installer named `tor-browser-windows-x86_64-portable-15.0.3.exe` to the Downloads directory.

**Action:**
File creation detected.

**File Path:**
`C:\Users\awl4114awl\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

**Evidence Source:**
`DeviceFileEvents`

---

### 2. Process Execution – Silent TOR Browser Installation

**Timestamp:**
January 9, 2026 – 06:21:49 AM

**Event:**
The user executed the TOR Browser portable installer from the Downloads directory using a silent installation switch (`/S`), resulting in background extraction of TOR Browser files without user prompts.

**Action:**
Process creation detected.

**Command Line:**
`tor-browser-windows-x86_64-portable-15.0.3.exe /S`

**File Path:**
`C:\Users\awl4114awl\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

**Evidence Source:**
`DeviceProcessEvents`

---

### 3. File Creation – TOR Browser Artifacts on Desktop

**Timestamp Range:**
January 9, 2026 – 06:22:05 AM to 06:22:26 AM

**Event:**
Following installation, multiple TOR Browser components were written to disk on the user’s desktop, including executable files, launcher shortcuts, and documentation artifacts associated with the TOR Browser package.

**Action:**
Multiple file creation events detected.

**Notable Files Created:**

* `tor.exe`
* `Tor Browser.lnk`
* `Tor-launcher.txt`
* `tor.txt`

**Example File Path:**
`C:\Users\awl4114awl\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

**Evidence Source:**
`DeviceFileEvents`

---

### 4. Process Execution – TOR Browser Launch

**Timestamp:**
January 9, 2026 – approximately 06:44:00 AM

**Event:**
The user launched TOR Browser, resulting in execution of TOR-related processes including `firefox.exe` (TOR Browser) and `tor.exe`. Multiple child processes were spawned, indicating an active browsing session.

**Action:**
Process creation events detected.

**Processes Observed:**

* `firefox.exe`
* `tor.exe`

**Evidence Source:**
`DeviceProcessEvents`

---

### 5. Network Activity – TOR Network Connections Established

**Timestamp Range:**
January 9, 2026 – 06:44:00 AM to 06:47:00 AM

**Event:**
TOR Browser successfully established anonymized network connections. Traffic was observed to local loopback addresses as well as external IP addresses over ports commonly associated with TOR relay and exit node communication.

**Action:**
Successful network connection events detected.

**Notable Indicators:**

* Loopback connections (`127.0.0.1`) on ports such as `9150`
* External connections over TOR-associated ports including `9000`, `9001`, and `9100`
* Encrypted outbound traffic initiated by `tor.exe`

**Evidence Source:**
`DeviceNetworkEvents`

---

### 6. File Creation – TOR Shopping List

**Timestamp:**
January 9, 2026 – 06:54:45 AM

**Event:**
The user created a text file named `tor-shopping-list.txt` on the desktop. The contents of the file included a list of fictitious illicit items, suggesting note-taking activity associated with TOR usage.

**Action:**
File creation and modification events detected.

**File Path:**
`C:\Users\awl4114awl\Desktop\tor-shopping-list.txt`

**Evidence Source:**
`DeviceFileEvents`

---

### Timeline Summary

The sequence of events demonstrates that the user `awl4114awl` intentionally downloaded, installed, and launched the TOR Browser on the endpoint `threat-hunt-lab`. The browser successfully established TOR network connectivity and was actively used for anonymized browsing. During the session, the user created and later deleted a text file titled `tor-shopping-list.txt`, indicating user-driven interaction beyond passive installation. This activity confirms unauthorized TOR usage on the endpoint.

---

### Summary

The threat hunting investigation confirmed unauthorized usage of the TOR Browser on the endpoint `threat-hunt-lab` by the user `awl4114awl`. Analysis of file, process, and network telemetry revealed that the user intentionally downloaded and executed the TOR Browser portable installer using a silent installation method, resulting in the extraction of TOR Browser components to the desktop.

Following installation, the user launched TOR Browser, which spawned multiple TOR-related processes and successfully established anonymized network connections to both local loopback addresses and external TOR relay and exit nodes over ports commonly associated with the TOR network. During the active TOR session, the user created and later deleted a text file named `tor-shopping-list.txt`, indicating deliberate user interaction beyond passive software installation.

The sequence and correlation of these events demonstrate confirmed TOR Browser usage, representing a potential policy violation due to the circumvention of standard network monitoring and security controls through anonymized browsing technology.

---

### Response Taken

Unauthorized TOR usage was confirmed on the endpoint `threat-hunt-lab`. In response, the device was isolated to prevent further anonymized network activity, and the incident was documented for management review. The user’s direct manager was notified of the findings.

In a production environment, additional follow-up actions would include conducting a user interview to determine intent, reviewing acceptable use policy compliance, and implementing preventative controls such as application allow-listing, enhanced endpoint monitoring, or network-level blocking of TOR entry nodes to reduce the likelihood of recurrence.

---
