"""Module 5: Map investigation clues to candidate MITRE ATT&CK techniques."""
import pandas as pd
from common import read_csv, write_csv

def main():
    inv = read_csv("investigation_report.csv")
    mappings = []
    for _, r in inv.iterrows():
        cmd = str(r.get("command_line", "")).lower()
        name = str(r.get("process_name", "")).lower()
        if "encodedcommand" in cmd or "-enc " in cmd:
            technique, tid, rationale = "Command and Scripting Interpreter: PowerShell", "T1059.001", "Encoded PowerShell-like command line; validate context"
        elif name in {"wscript.exe", "cscript.exe", "mshta.exe"}:
            technique, tid, rationale = "Command and Scripting Interpreter", "T1059", "Script-capable process observed; validate parent and command line"
        else:
            technique, tid, rationale = "Execution (candidate)", "T1059", "Heuristic candidate requiring analyst confirmation"
        mappings.append({
            "event_id": r.get("event_id", ""), "host": r.get("host", ""),
            "process_name": r.get("process_name", ""), "technique_id": tid,
            "technique_name": technique, "rationale": rationale,
            "confidence": "Low - heuristic", "confirmed": False
        })
    write_csv(pd.DataFrame(mappings), "attack_mapping.csv")
    print("Module 5 complete. Candidate mappings must be reviewed by an analyst.")

if __name__ == "__main__":
    main()
