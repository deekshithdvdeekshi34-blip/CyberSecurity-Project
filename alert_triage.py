"""Module 3: Explainable demo risk scoring and severity triage."""
from common import read_csv, write_csv

def main():
    df = read_csv("scored_events.csv", ["event_id", "anomaly_score", "failed_logins", "file_changes", "process_count", "network_connections"])
    alerts = []
    for _, r in df.iterrows():
        reasons = []
        risk = float(r["anomaly_score"]) * 0.45
        if r["failed_logins"] >= 10:
            risk += 20; reasons.append(f"high failed logins ({int(r['failed_logins'])})")
        if r["file_changes"] >= 100:
            risk += 20; reasons.append(f"high file changes ({int(r['file_changes'])})")
        if r["process_count"] >= 100:
            risk += 10; reasons.append(f"high process count ({int(r['process_count'])})")
        if r["network_connections"] >= 100:
            risk += 10; reasons.append(f"high network connections ({int(r['network_connections'])})")
        risk = round(min(100, risk), 1)
        if risk >= 80: severity = "Critical"
        elif risk >= 60: severity = "High"
        elif risk >= 35: severity = "Medium"
        else: severity = "Low"
        if risk >= 35 or int(r.get("anomaly_label", 0)) == 1:
            alerts.append({
                "alert_id": f"ALT-{r['event_id']}", "event_id": r["event_id"],
                "timestamp": r.get("timestamp", ""), "host": r.get("host", ""),
                "user": r.get("user", ""), "risk_score": risk, "severity": severity,
                "reasons": "; ".join(reasons) if reasons else "model flagged unusual behavior",
                "status": "New"
            })
    out = __import__("pandas").DataFrame(alerts, columns=["alert_id","event_id","timestamp","host","user","risk_score","severity","reasons","status"])
    write_csv(out, "security_alerts.csv")
    print("Module 3 complete. Scores and thresholds are illustrative, not calibrated probabilities.")

if __name__ == "__main__":
    main()
