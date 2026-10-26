"""Module 1: Generate a safe synthetic endpoint event collection."""
import numpy as np
import pandas as pd
from common import DATA, ensure_dirs, write_csv

def main():
    ensure_dirs()
    rng = np.random.default_rng(17)
    n = 240
    hosts = ["WS-001", "WS-002", "FIN-014", "ENG-022", "HR-005"]
    users = ["alex", "sam", "jordan", "taylor", "casey"]
    now = pd.Timestamp.now().floor("min")
    rows, features, procs = [], [], []
    for i in range(n):
        suspicious = (i % 29 == 0 or i % 41 == 0)
        host = hosts[int(rng.integers(0, len(hosts)))]
        user = users[int(rng.integers(0, len(users)))]
        ts = now - pd.Timedelta(minutes=int((n-i)*7))
        failed = int(rng.poisson(2))
        files = int(rng.poisson(12))
        proc_count = int(rng.integers(15, 65))
        net = int(rng.poisson(20))
        login_hour = int(ts.hour)
        if suspicious:
            failed = int(rng.integers(12, 30))
            files = int(rng.integers(110, 260))
            proc_count = int(rng.integers(100, 180))
            net = int(rng.integers(130, 280))
            login_hour = int(rng.choice([0, 1, 2, 3, 4]))
        event_id = f"EVT-{i+1:04d}"
        rows.append({
            "event_id": event_id, "timestamp": ts.isoformat(), "host": host, "user": user,
            "event_type": str(rng.choice(["process_start", "login", "file_change", "network_connection"])),
            "source": "synthetic_demo", "failed_logins": failed, "file_changes": files,
            "process_count": proc_count, "network_connections": net, "login_hour": login_hour,
            "source_ip": f"192.0.2.{int(rng.integers(1, 250))}"
        })
        features.append({
            "event_id": event_id, "timestamp": ts.isoformat(), "host": host, "user": user,
            "failed_logins": failed, "file_changes": files, "process_count": proc_count,
            "network_connections": net, "login_hour": login_hour
        })
    proc_names = ["explorer.exe", "chrome.exe", "python.exe", "powershell.exe", "notepad.exe", "wscript.exe"]
    for i in range(100):
        suspicious = i % 13 == 0
        pid = 2000 + i
        parent_pid = 1000 if i % 4 else 1200
        pname = "powershell.exe" if suspicious else proc_names[int(rng.integers(0, len(proc_names)))]
        cmd = "powershell.exe -EncodedCommand DEMO_ONLY" if suspicious else f'"C:\\Program Files\\{pname}"'
        procs.append({
            "timestamp": (now - pd.Timedelta(minutes=100-i)).isoformat(),
            "host": hosts[i % len(hosts)], "user": users[i % len(users)],
            "pid": pid, "parent_pid": parent_pid, "process_name": pname,
            "command_line": cmd, "process_guid": f"{{DEMO-{i+1:04d}}}",
            "parent_process_guid": f"{{DEMO-PARENT-{parent_pid}}}",
            "event_id": f"PROC-{i+1:04d}"
        })
    write_csv(pd.DataFrame(rows), "endpoint_events.csv")
    write_csv(pd.DataFrame(features), "endpoint_features.csv")
    write_csv(pd.DataFrame(procs), "process_events.csv")
    print("Module 1 complete: synthetic endpoint telemetry created.")

if __name__ == "__main__":
    main()
