"""Module 9: Build a SHA-256 evidence inventory and human-readable incident summary."""
import hashlib
from datetime import datetime, timezone
import pandas as pd
from common import DATA, REPORTS, ensure_dirs, read_csv, write_csv

EVIDENCE_FILES = ["endpoint_events.csv", "endpoint_features.csv", "process_events.csv", "scored_events.csv",
                  "security_alerts.csv", "investigation_report.csv", "attack_mapping.csv",
                  "correlated_incidents.csv", "threat_intelligence.csv", "response_actions.csv"]

def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    ensure_dirs()
    rows = []
    for name in EVIDENCE_FILES:
        path = DATA / name
        if path.exists():
            rows.append({
                "evidence_id": f"EVD-{len(rows)+1:03d}", "file_name": name,
                "sha256": sha256_file(path), "size_bytes": path.stat().st_size,
                "collected_utc": datetime.now(timezone.utc).isoformat(),
                "integrity_note": "Hash recorded after pipeline output; protect original files"
            })
    write_csv(pd.DataFrame(rows), "evidence_inventory.csv")
    alerts = read_csv("security_alerts.csv")
    incidents = read_csv("correlated_incidents.csv")
    high = int(alerts["severity"].isin(["Critical", "High"]).sum()) if not alerts.empty else 0
    critical = int((alerts["severity"] == "Critical").sum()) if not alerts.empty else 0
    REPORTS.mkdir(exist_ok=True)
    report = f"""# ETDR Demonstration Incident Summary

- Generated (UTC): {datetime.now(timezone.utc).isoformat()}
- Alerts: {len(alerts)}
- Critical alerts: {critical}
- High or Critical alerts: {high}
- Correlated incident groups: {len(incidents)}
- Evidence inventory entries: {len(rows)}

## Interpretation
This report summarizes a synthetic educational dataset. Alert scores are heuristic/anomaly-model outputs,
not calibrated probabilities. Candidate ATT&CK mappings and investigation clues require analyst validation.
The response module is simulation-only and did not change endpoints.

## Suggested analyst workflow
1. Validate the alert and confirm host/user/time context.
2. Review process ancestry and command-line details.
3. Correlate authentication, process, file, and network events.
4. Check trusted threat-intelligence sources where authorized.
5. Preserve evidence and record chain-of-custody details.
6. Obtain explicit approval before any real containment action.
"""
    (REPORTS / "incident_report.md").write_text(report, encoding="utf-8")
    print(f"Saved: reports/incident_report.md")
    print("Module 9 complete.")

if __name__ == "__main__":
    main()
