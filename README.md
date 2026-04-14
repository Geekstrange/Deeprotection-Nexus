# Deeprotection Nexus

Deeprotection Nexus is the next‑generation web management platform for the Deeprotection security suite. It is far more than a simple GUI — it is a multi‑function aggregation control center that unifies monitoring, configuration, policy management, log auditing, and task scheduling into a single cockpit.

## Features

### 1. System Overview
Displays key info like protection status, expiration time, and protection count.

**Preview:**  
![System Overview](https://github.com/Geekstrange/Deeprotection-WebGUI/blob/main/img/system-overview.png "System Overview Interface")

### 2. Configuration Management
Set basic configurations like language, protection switch, and auto-update.

**Preview:**  
![Configuration Management](https://github.com/Geekstrange/Deeprotection-WebGUI/blob/main/img/config-management.png "Configuration Management Interface")

### 3. Rule Management
Manage protected paths and command interception rules.

**Preview:**  
![Rule Management](https://github.com/Geekstrange/Deeprotection-WebGUI/blob/main/img/rule-management.png "Rule Management Interface")

### 4. Log Viewing
View system protection logs in real time.

**Preview:**  
![Log Viewing](https://github.com/Geekstrange/Deeprotection-WebGUI/blob/main/img/log-viewing.png "Real-time Log View")

### 5. Terminal Tool
Execute system commands for debugging and management.

**Preview:**  
![Terminal Tool](https://github.com/Geekstrange/Deeprotection-WebGUI/blob/main/img/terminal-tool.png "Terminal Tool Interface")

---

5. Run ./dn -host 127.0.0.1-port 8080

## Configuration File

The configuration file is located at `/etc/deeprotection/config.toml` and includes:

- `language`: UI language setting.
- `mode`: Protection mode (disable / permissive / Enforcing).

It also contains the list of protected paths and command interception rules.

## Logs

System logs are stored in `/var/log/dp.log` and can be viewed in real time via the "Log Viewing" page in the web interface.

## License

This project is under the Apache License 2.0. See the [LICENSE](https://github.com/Geekstrange/Deeprotection-Nexus?tab=Apache-2.0-1-ov-file) file for details.
