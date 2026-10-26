from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"

def ensure_dirs():
    DATA.mkdir(exist_ok=True)
    MODELS.mkdir(exist_ok=True)
    REPORTS.mkdir(exist_ok=True)

def read_csv(name, required=None):
    path = DATA / name
    if not path.exists():
        raise FileNotFoundError(f"Missing {path.name}. Run `python run_all.py` or the required earlier module first.")
    df = pd.read_csv(path)
    if required:
        missing = [c for c in required if c not in df.columns]
        if missing:
            raise ValueError(f"{path.name} is missing columns: {missing}")
    return df

def write_csv(df, name):
    ensure_dirs()
    path = DATA / name
    df.to_csv(path, index=False)
    print(f"Saved: {path.relative_to(ROOT)} ({len(df)} rows)")
    return path
