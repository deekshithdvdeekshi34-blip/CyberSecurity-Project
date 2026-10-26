"""Module 7: Offline threat-intelligence enrichment using reserved example IP ranges."""
import pandas as pd
from common import read_csv, write_csv

# Documentation/example addresses only; never queried externally.
DEMO_INTEL = {
    "192.0.2.13": {"verdict": "demo_suspicious", "source": "offline_demo_feed", "note": "Synthetic example entry"},
    "198.51.100.23": {"verdict": "unknown", "source": "offline_demo_feed", "note": "Reserved documentation range"},
    "203.0.113.7": {"verdict": "unknown", "source": "offline_demo_feed", "note": "Reserved documentation range"},
}

def main():
    events = read_csv("endpoint_events.csv", ["event_id", "source_ip"])
    rows = []
    for _, r in events.iterrows():
        ip = str(r["source_ip"])
        intel = DEMO_INTEL.get(ip, {"verdict": "not_in_demo_feed", "source": "offline_demo_feed", "note": "No match in local sample feed"})
        rows.append({"event_id": r["event_id"], "source_ip": ip, **intel, "lookup_mode": "offline-only"})
    write_csv(pd.DataFrame(rows), "threat_intelligence.csv")
    print("Module 7 complete. This uses an offline demo feed; no external lookups or API keys.")

if __name__ == "__main__":
    main()
