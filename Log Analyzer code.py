import argparse
import os
import pandas as pd

# Windows Event Log (requires pywin32)
try:
    import win32evtlog
    WINDOWS_SUPPORT = True
except ImportError:
    WINDOWS_SUPPORT = False

def parse_linux_logs(log_file):
    """Parse Linux logs for failed login attempts and suspicious activity."""
    if not os.path.exists(log_file):
        print(f"Error: {log_file} does not exist.")
        return

    with open(log_file, 'r') as f:
        logs = f.readlines()

    suspicious_entries = [line for line in logs if "failed" in line.lower() or "unauthorized" in line.lower()]
    
    df = pd.DataFrame(suspicious_entries, columns=["Log Entry"])
    df.to_csv("linux_log_report.csv", index=False)
    print("[+] Linux log analysis complete. Report saved as linux_log_report.csv")


def parse_windows_logs(event_type):
    """Parse Windows Event Viewer logs for security events."""
    if not WINDOWS_SUPPORT:
        print("Error: Windows Event Log support requires pywin32.")
        return
    
    server = None  # Local machine
    log_type = event_type
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = []
    
    while True:
        records = win32evtlog.ReadEventLog(hand, flags, 0)
        if not records:
            break
        for event in records:
            events.append(event.StringInserts)
    
    df = pd.DataFrame(events, columns=["Event Details"])
    df.to_csv("windows_log_report.csv", index=False)
    print("[+] Windows log analysis complete. Report saved as windows_log_report.csv")


def main():
    parser = argparse.ArgumentParser(description="Log Analyzer for Linux and Windows")
    parser.add_argument("--linux", help="Path to Linux log file")
    parser.add_argument("--windows", help="Windows Event Log type (e.g., Security, System)")
    
    args = parser.parse_args()
    
    if args.linux:
        parse_linux_logs(args.linux)
    elif args.windows:
        parse_windows_logs(args.windows)
    else:
        print("Usage: python log_analyzer.py --linux <logfile> OR --windows <EventLogType>")

if __name__ == "__main__":
    main()
