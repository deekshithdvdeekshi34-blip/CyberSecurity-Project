"""Module 2: Isolation Forest behavioral anomaly detection."""
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from common import DATA, MODELS, ensure_dirs, read_csv, write_csv

FEATURES = ["failed_logins", "file_changes", "process_count", "network_connections", "login_hour"]

def main():
    ensure_dirs()
    df = read_csv("endpoint_features.csv", ["event_id", *FEATURES])
    x = df[FEATURES].fillna(0)
    scaler = StandardScaler()
    xs = scaler.fit_transform(x)
    model = IsolationForest(n_estimators=150, contamination=0.04, random_state=42)
    pred = model.fit_predict(xs)
    raw = model.decision_function(xs)
    # Convert relative outlierness into an easy-to-read 0-100 demo score.
    outlierness = 1 - (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)
    df["anomaly_label"] = (pred == -1).astype(int)
    df["anomaly_score"] = (outlierness * 100).round(1)
    joblib.dump(model, MODELS / "isolation_forest.joblib")
    joblib.dump(scaler, MODELS / "scaler.joblib")
    write_csv(df, "scored_events.csv")
    plt.figure(figsize=(9, 4))
    plt.hist(df["anomaly_score"], bins=20)
    plt.title("Synthetic Endpoint Anomaly Score Distribution")
    plt.xlabel("Relative anomaly score (0–100; not a probability)")
    plt.ylabel("Event count")
    plt.tight_layout()
    plt.savefig(DATA / "anomaly_scores.png", dpi=130)
    plt.close()
    print("Module 2 complete. Model and plot saved.")

if __name__ == "__main__":
    main()
