# Log Analyzer – Parse System Logs for Suspicious Activity

## Overview

This tool analyzes system logs, including Linux syslogs and Windows Event Viewer logs, to detect suspicious activities such as failed login attempts, unauthorized access, and error patterns.

## Features

- Parse Linux syslog files (`/var/log/syslog`, `/var/log/auth.log`)
- Read Windows Event Logs via `win32evtlog` (requires Windows)
- Detect common security threats such as brute-force attacks and privilege escalations
- Export findings to a report file

## Requirements

For Linux:

```bash
pip install pandas
```

For Windows:

```bash
pip install pywin32 pandas
```

## Usage

### On Linux:

```bash
python log_analyzer.py --linux /var/log/auth.log
```

### On Windows:

```powershell
python log_analyzer.py --windows Security
```

## Disclaimer

This tool is for security monitoring and forensic analysis. Unauthorized access or improper use may violate laws.

## License

MIT License.
