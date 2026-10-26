# Endpoint Threat Detection and Response (ETDR)

A learning/demo SOC workflow that runs locally in VS Code. The included data is synthetic.
It demonstrates event collection, anomaly scoring, alert triage, investigation, ATT&CK candidate mapping,
incident correlation, threat-intelligence enrichment, response simulation, evidence inventory, and dashboarding.

## Requirements
- Windows 10/11
- Python 3.10–3.13
- VS Code with the Python extension

## Setup (PowerShell terminal in VS Code)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python run_all.py
streamlit run dashboard.py
```
If PowerShell blocks activation, use:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run_all.py
.\.venv\Scripts\python.exe -m streamlit run dashboard.py
```

## Output
- `data/endpoint_events.csv`: synthetic endpoint telemetry
- `data/endpoint_features.csv`: endpoint behavior features
- `data/process_events.csv`: synthetic process events
- `data/scored_events.csv`: anomaly scores
- `data/security_alerts.csv`: triaged alerts
- `data/investigation_report.csv`: investigation indicators
- `data/attack_mapping.csv`: candidate ATT&CK mappings
- `data/correlated_incidents.csv`: correlated event groups
- `data/threat_intelligence.csv`: offline demo enrichment
- `data/response_actions.csv`: simulated response actions
- `data/evidence_inventory.csv`: evidence inventory and SHA-256 hashes
- `reports/incident_report.md`: generated summary report

## Run one module at a time
```powershell
python generate_data.py
python anomaly_detector.py
python alert_triage.py
python threat_investigation.py
python attack_mapping.py
python incident_correlation.py
python threat_intelligence.py
python response_simulator.py
python evidence_report.py
streamlit run dashboard.py
```
Run `python run_all.py` to execute the pipeline in order.

## Safety and limitations
- Data is generated for demonstration and is not evidence of real attacks.
- Anomaly scores and thresholds are illustrative, not calibrated probabilities.
- ATT&CK mappings are candidates for analyst review, not confirmed attribution.
- Response actions are simulated and do not block accounts, kill processes, or change firewall rules.
- For real logs, collect only from systems you own or are authorized to monitor. Validate schemas and protect sensitive logs.
