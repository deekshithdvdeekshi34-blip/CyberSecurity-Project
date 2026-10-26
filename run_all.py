"""Run Modules 1–9 in sequence; Module 10 is the Streamlit dashboard."""
import subprocess
import sys

SCRIPTS = [
    "generate_data.py",
    "anomaly_detector.py",
    "alert_triage.py",
    "threat_investigation.py",
    "attack_mapping.py",
    "incident_correlation.py",
    "threat_intelligence.py",
    "response_simulator.py",
    "evidence_report.py",
]

def main():
    for script in SCRIPTS:
        print(f"\n{'='*12} Running {script} {'='*12}", flush=True)
        result = subprocess.run([sys.executable, script], check=False)
        if result.returncode != 0:
            raise SystemExit(f"Stopped: {script} failed with exit code {result.returncode}")
    print("\nAll pipeline modules completed. Start dashboard with: streamlit run dashboard.py")

if __name__ == "__main__":
    main()
