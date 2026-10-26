"""Module 8: Simulate response recommendations without changing the endpoint."""
import pandas as pd
from common import read_csv, write_csv

def main():
    alerts = read_csv("security_alerts.csv")
    actions = []
    for _, r in alerts.iterrows():
        if r["severity"] in {"Critical", "High"}:
            recommendation = "Request analyst approval for containment; preserve evidence first"
        elif r["severity"] == "Medium":
            recommendation = "Collect additional telemetry and investigate"
        else:
            recommendation = "Monitor and close only if validated benign"
        actions.append({
            "action_id": f"ACT-{r['alert_id']}", "alert_id": r["alert_id"],
            "host": r.get("host", ""), "severity": r["severity"],
            "recommended_action": recommendation, "execution_mode": "SIMULATION_ONLY",
            "approval_status": "Pending analyst approval", "executed": False,
            "result": "No endpoint changes performed"
        })
    write_csv(pd.DataFrame(actions, columns=["action_id","alert_id","host","severity","recommended_action","execution_mode","approval_status","executed","result"]), "response_actions.csv")
    print("Module 8 complete. No processes, accounts, network connections, or firewall rules were changed.")

if __name__ == "__main__":
    main()
