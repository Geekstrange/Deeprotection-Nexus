# Deeprotection WebGUI

Deeprotection WebGUI is a web interface tool for managing Deeprotection. It offers an intuitive interface for configuring protection rules, viewing system status and logs, etc.

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

5. Open a browser and visit `http://127.0.0.1:8080` (default address, modifiable in settings).

## Configuration File

The configuration file is located at `/etc/deeprotection/deeprotection.conf` and includes:

- `web_ip`: The IP address the web service binds to.
- `web_port`: The port the web service listens on.
- `language`: UI language setting.
- `disable`: Whether to disable protection.
- `expire_hours`: Protection disable expiration time (in hours).
- `update`: Whether to enable auto-update.
- `mode`: Protection mode (Permissive/Enhanced).

It also contains the list of protected paths and command interception rules.

## Logs

System logs are stored in `/var/log/deeprotection.log` and can be viewed in real time via the "Logs" page in the web interface.

## License

This project is under the Apache License 2.0. See the [LICENSE](https://github.com/Geekstrange/Deeprotection-WebGUI?tab=Apache-2.0-1-ov-file) file for details.