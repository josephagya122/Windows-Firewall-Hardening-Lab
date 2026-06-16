# Host-Based Network Isolation & Threat Telemetry Lab

## 📌 Executive Summary
* **Assessor:** Joseph Agyapong
* **Target Asset:** Windows Server (IP: `172.16.0.1`)
* **Source Asset:** Windows 10 Workstation (IP: `172.16.0.100`)
* **Objective:** Mitigate lateral movement vectors via Remote Desktop Protocol (RDP) by implementing a host-based network control, validating defensive enforcement, and analyzing raw security event logs.

---

## 🛠️ Environment Protocols & Topology
* **Hypervisor:** Oracle VirtualBox
* **Internal Network Subnet:** `172.16.0.0/24`
* **Defensive Application:** Windows Defender Firewall with Advanced Security (WDFAS)
* **Log Parser:** Administrative PowerShell Core

---

## 🚀 Phase 1: Baseline Testing (Pre-Control Evaluation)

The objective of this phase was to verify open network communication between assets to establish a verified baseline prior to deploying security restrictions.

### 1.1 Network Layer Verification
* **Action:** Initiated an outbound RDP session (`mstsc.exe`) from the Windows 10 Client (`172.16.0.100`) targeting the Windows Server (`172.16.0.1`).
* **Observation:** The network path successfully routed the connection, confirming no initial firewall roadblocks.

### 1.2 Access Policy Standardization
* **Issue Encountered:** The default local user account (`joeA`) triggered an operating system restriction error: 
  > *"The connection was denied because the user account is not authorized for remote login."*
* **Remediation:** Switched authentication context to the local `Administrator` account to isolate network path capabilities from local user privileges.
* **Result:** **Success.** A functional desktop session was achieved, proving a clear network baseline path.

---

## 🛡️ Phase 2: Control Implementation (Security Engineering)

The objective of this phase was to engineer host-level barriers and activate advanced telemetry gathering for auditing.

### 2.1 Auditing & Telemetry Activation
By default, Windows silently drops blocked connections without maintaining an inspection history. Advanced auditing was explicitly enabled:
1. Executed `wf.msc` on the **Windows Server**.
2. Accessed **Properties** and modified the **Domain**, **Private**, and **Public** profiles.
3. Changed **Logging** $\rightarrow$ **Log dropped packets** to **Yes**.
4. Log Path Target: `C:\Windows\System32\LogFiles\Firewall\pfirewall.log`

### 2.2 Defensive Inbound Rule Architecture
A custom rule was deployed to reject incoming RDP requests from the specific client machine.

| Rule Attribute | Configuration Value |
| :--- | :--- |
| **Rule Name** | `SOC-Lab-Block-Unauthorized-RDP-Lateral-Movement` |
| **Protocol Type** | TCP |
| **Local Port** | `3389` (Remote Desktop Protocol) |
| **Scope: Local IP** | Any IP Address |
| **Scope: Remote IP** | `172.16.0.100` (Explicit Attacker Workstation) |
| **Action** | **Block the connection** |
| **Profile Rule Match** | Domain, Private, Public |

> ⚠️ **Engineering Troubleshooting Note:** During deployment, the attacker IP was initially misconfigured inside the *Local IP* scope attribute, causing a control bypass. The rule logic was systematically evaluated and updated to place `172.16.0.100` strictly in the **Remote IP** scope to enforce proper mitigation.

---

## 🧪 Phase 3: Control Verification (Security Posture Testing)

The objective of this phase was to simulate an unauthorized pivot attack to confirm control efficacy.

### 3.1 Adversarial Attack Simulation
* **Action:** Attempted to re-establish an RDP session from the Windows 10 Client using the verified Administrator credentials.
* **Observation:** The Remote Desktop UI remained frozen at the "Connecting..." stage, indicating silent dropping of ingress traffic.
* **Result:** **Control Functional.** The session timed out entirely with a network connection error. The host-level control successfully neutralized the lateral threat.

---

## 📊 Phase 4: Log Analysis & Forensic Telemetry

The objective of this phase was to parse and analyze endpoint logging data to confirm event generation for security intelligence tracking.

### 4.1 Telemetry Extraction via PowerShell
An administrative PowerShell console was leveraged on the target Windows Server to grep for explicit drop logs targeting the endpoint:

```powershell
Get-Content -Path "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" -Tail 20 | Select-String "DROP"
