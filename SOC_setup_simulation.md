# ⚙️ SOC Setup  

This guide documents the technical setup of the SOC components used in the project. It integrates **SIEM**, **SOAR**, **EDR**, **monitoring**, **network analysis**, as well as **forensic and vulnerability assessment tools**, all deployed within a virtualized infrastructure using the **Airbus CyberRange** environment.



---

## 🖥️ Infrastructure Overview

- **Environment**: Airbus CyberRange (virtual cyber simulation platform)
- **Virtual Machines**:
  - Debian 11 → Zeek, Shuffle
  - Ubuntu 22.04 → Zabbix, Splunk, Wazuh
  - Windows 11 → Endpoint simulation (user workstation, attack target)
  - pfSense → Network firewall and segmentation
- **Network Segmentation**:
  - `192.168.128.0/24` → DMZ (FTP, Webserver, Proxy)
  - `192.168.130.0/24` → Server LAN (AD, Mail)
  - `192.168.131.0/24` → Admin LAN (Admin hosts)
  - `192.168.132.0/24` → User LAN (Users)
  - `192.168.134.0/24` → SOC LAN (Splunk, Syslog, Wazuh, Zabbix, SOAR)

---

## 🧩 Components and Setup


### 🔍 1. Splunk (SIEM)

**Goal**: Collect, index, and correlate logs from various sources.

#### Setup:
```bash
wget -O splunk.deb 'https://download.splunk.com/...'
dpkg -i splunk.deb
/opt/splunk/bin/splunk start --accept-license
```

#### Configuration:
- Forward logs via Syslog from Wazuh, Zeek, endpoints.
- Configure inputs in `inputs.conf`.
- Create custom alert rules (e.g., high SSH login failures).
- Define indexes and sourcetypes.

#### Example alert:
- SSH brute force (triggered by 10+ failed logins within 60s)

---

### 🛡 2. Wazuh (EDR / HIDS)

**Goal**: Monitor and analyze system activity on endpoints.

#### Setup:
- Deploy Wazuh manager and dashboard on a server.
- Install Wazuh agents on endpoints.

#### Example agent install:
```bash
curl -s https://packages.wazuh.com/install.sh | sudo bash
```

#### Configuration:
- Enable modules: `syscheck`, `rootcheck`, `auth`, `firewalld`
- Link logs to Splunk via **Filebeat** (alerts.json) or **direct forwarding via Syslog or Wazuh’s native Splunk module**.

#### Use cases:
- Unauthorized sudo access
- Suspicious file changes
- Bruteforce SSH attempts

---

### ⚡ 3. Shuffle (SOAR)

**Goal**: Automate response to Splunk alerts using workflows.

#### Setup:
- Deploy Shuffle via Docker:
```bash
git clone https://github.com/frikky/Shuffle.git
cd Shuffle
docker-compose up -d
```

#### Configuration:
- Create API keys for integration with Splunk.
- Build workflows: parse alert → block IP (e.g., via IPTables) → notify team.

#### Example workflow:
- Receive Splunk alert
- Extract attacker IP
- Execute remote SSH command to block IP on firewall
- Send email to SOC

---

### 📊 4. Zabbix (Monitoring)

**Goal**: Monitor service uptime, system performance, and resource usage.

#### Setup:
- Deploy Zabbix server and web interface
- Install Zabbix agents on all hosts

#### Configuration:
- Host templates: Linux OS, SSH service
- Triggers: memory usage, CPU load, service down

---

### 🌐 5. Zeek (Network Analysis)

**Goal**: Passively monitor and log network activity for forensic analysis.

#### Setup:
```bash
apt install zeek
zeekctl deploy
```

#### Logs:
- `conn.log`, `ssh.log`, `http.log`, `dns.log`
- Forwarded to Splunk via Filebeat or manually ingested

#### Use case:
- Detect SSH brute force or scan based on abnormal traffic behavior

---

### 📥 6. Syslog Server (Log Centralization)

**Goal**: Collect logs from various hosts and forward them to Splunk.

#### Setup:
- Use **rsyslog** or **syslog-ng** as the log collection service.
- Configure listeners on **port 514/UDP** for incoming Syslog traffic.
- Forward collected logs to the **Splunk ingestion port** (via TCP/UDP or HTTP Event Collector depending on configuration).

#### Example (rsyslog forwarding):
Edit `/etc/rsyslog.conf` or `/etc/rsyslog.d/50-default.conf`:
`*.* @<splunk_ip>:514`

- Restart rsyslog: `sudo systemctl restart rsyslog`

#### Notes:
- Ensure firewall rules allow traffic on port 514.
- Logs can be tagged by source/host for better indexing in Splunk.


---

### 🛠 7. OpenVAS (Vulnerability Scanner)

**Goal**: Identify and report system and network vulnerabilities.

#### Setup:
- `sudo apt install openvas`
- `sudo gvm-setup`

#### Usage:
- Schedule scans on internal subnets.
- Export reports for SOC analysis.
- Classify risks: CVEs, outdated services, weak configurations.

---

### 🕵️ 8. Autopsy (Forensics)

**Goal**: Investigate compromised systems and analyze disk-level evidence.

#### Setup:
- Download and install **Autopsy** on a forensic workstation.
- Acquire disk image from the suspected machine.

#### Features:
- File recovery and timeline analysis.
- Browser history and deleted file tracing.
- Supports evidence preservation and incident reporting.

---

## 🧪 Attack Scenarios Simulated

### Scenario 1: SSH Brute-force Attack
- Tool: `hydra`
- Impact: Excessive login attempts
- Detection: Wazuh (auth.log), Zeek (connection count), Splunk alert
- Response: IP blocked by Shuffle, email sent to analyst

### Scenario 2: Port Scanning
- Tool: `nmap`
- Detection: Zeek (`conn.log`), alert in Splunk
- Response: Visualized in dashboard, IP tagged in logs

---

## ✅ Lessons Learned

- Centralized logging and normalization are essential for alert correlation.
- SOAR automation reduces manual workload.
- Combining host-based (Wazuh) and network-based (Zeek) monitoring increases visibility.
- Splunk’s alert flexibility is key for SOC responsiveness.
- Regular scanning with OpenVAS helps in proactive hardening.
- Autopsy enables post-compromise analysis for deeper understanding.

---

## 🧩 Tools Version

- Splunk: 9.0.x
- Wazuh: 4.7.x
- Shuffle: Latest GitHub build (Docker)
- Zabbix: 6.x
- Zeek: 5.x
- OpenVAS: 22.x+
- Autopsy: 4.20.x

---

## 🧠 References

- [Splunk Docs](https://docs.splunk.com/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Shuffle SOAR](https://github.com/frikky/Shuffle)
- [Zabbix](https://www.zabbix.com/)
- [Zeek](https://zeek.org/)
- [OpenVAS](https://www.greenbone.net/en/)
- [Autopsy](https://www.sleuthkit.org/autopsy/)
