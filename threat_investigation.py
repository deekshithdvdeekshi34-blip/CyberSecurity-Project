"""Module 4: Basic process review and parent-child investigation clues."""
import pandas as pd
from common import read_csv, write_csv

def main():
    df = read_csv("process_events.csv", ["timestamp", "host", "pid", "parent_pid", "process_name", "command_line"])
    findings = []
    for _, r in df.iterrows():
        cmd = str(r["command_line"]).lower()
        name = str(r["process_name"]).lower()
        clues = []
        if name in {"powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
            clues.append("script-capable process: review context")
        if "encodedcommand" in cmd or "-enc " in cmd:
            clues.append("encoded-command indicator: inspect command and parent")
        if clues:
            findings.append({**r.to_dict(), "investigation_clues": "; ".join(clues), "review_status": "Needs analyst review"})
    out = pd.DataFrame(findings)
    write_csv(out, "investigation_report.csv")
    print("Module 4 complete. Process names/command lines are clues, not proof of maliciousness.")

if __name__ == "__main__":
    main()
