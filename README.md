# Deeprotection Nexus

Deeprotection Nexus is the next‑generation web management platform for the Deeprotection security suite. It is far more than a simple GUI — it is a multi‑function aggregation control center that unifies monitoring, configuration, policy management, log auditing, and task scheduling into a single cockpit.

## Features

### 1. Login Page
The web interface is secured by a password-based login; the first login sets the password hash.

**Preview:**  
![Login Page](https://github.com/Geekstrange/Deeprotection-Nexus/blob/main/img/login.png "Login Interface")

### 2. System Overview
Displays key info like protection status, expiration time, and protection count.

**Preview:**  
![System Overview](https://github.com/Geekstrange/Deeprotection-Nexus/blob/main/img/system-overview.png "System Overview Interface")

### 3. Rule Management
Manage protected paths and command interception rules.

**Preview:**  
![Rule Management](https://github.com/Geekstrange/Deeprotection-Nexus/blob/main/img/rule-management.png "Rule Management Interface")

### 4. Log Viewing
View system protection logs in real time via Server-Sent Events (SSE).

**Preview:**  
![Log Viewing](https://github.com/Geekstrange/Deeprotection-Nexus/blob/main/img/log-viewing.png "Real-time Log View")

### 5. Plugin Management
Install, enable, disable, and remove plugins to extend the platform's capabilities. Plugins are distributed as ZIP archives containing a `plugin.json` manifest.

**Preview:**  
![Rule Management](https://github.com/Geekstrange/Deeprotection-Nexus/blob/main/img/plugin-management.png "Plugin Management Interface")

---

## Quick Start

Run the server with a custom listen address:

```bash
./dn -listen 127.0.0.1:8080
```

The default listen address is `127.0.0.1:80`. After startup, open `http://127.0.0.1:8080` in your browser. You will be redirected to the login page.

## Configuration File

The configuration file is located at `/etc/deeprotection/config.toml` and includes:

- `core.mode`: Protection mode (`disable`, `permissive`, or `enforcing`).
- `auth.password_hash`: SHA-256 hex digest of the admin password.
- `paths.protect`: List of protected file/directory paths.
- `rules`: Array of command interception rules.

## Logs

System logs are stored in `/var/log/audit.log` (JSON Lines format) and can be viewed in real time via the "Log Viewing" page in the web interface.

## License

This project is under the Apache License 2.0. See the [LICENSE](https://github.com/Geekstrange/Deeprotection-Nexus?tab=Apache-2.0-1-ov-file) file for details.