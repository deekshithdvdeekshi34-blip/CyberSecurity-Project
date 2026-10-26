"""Module 6: Group related alerts by host and a rolling time window."""
import pandas as pd
from common import read_csv, write_csv

def main():
    alerts = read_csv("security_alerts.csv")
    if alerts.empty:
        write_csv(pd.DataFrame(columns=["incident_id","host","first_seen","last_seen","alert_count","max_risk","severity","alert_ids"]), "correlated_incidents.csv")
        return
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"], errors="coerce")
    alerts = alerts.sort_values(["host","timestamp"])
    incidents = []
    for host, group in alerts.groupby("host"):
        group = group.copy()
        group["bucket"] = group["timestamp"].dt.floor("2h").astype(str)
        for bucket, sub in group.groupby("bucket"):
            max_risk = float(sub["risk_score"].max())
            severity = "Critical" if max_risk >= 80 else "High" if max_risk >= 60 else "Medium" if max_risk >= 35 else "Low"
            incidents.append({
                "incident_id": f"INC-{host}-{len(incidents)+1:03d}", "host": host,
                "first_seen": sub["timestamp"].min(), "last_seen": sub["timestamp"].max(),
                "alert_count": len(sub), "max_risk": max_risk, "severity": severity,
                "alert_ids": "; ".join(sub["alert_id"].astype(str).tolist())
            })
    write_csv(pd.DataFrame(incidents), "correlated_incidents.csv")
    print("Module 6 complete. Correlation is a simple host/time heuristic.")

if __name__ == "__main__":
    main()
