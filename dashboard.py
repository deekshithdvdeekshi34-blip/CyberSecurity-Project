import pandas as pd
import plotly.express as px
import streamlit as st
from pathlib import Path

# ==============================
# ETDR SOC DASHBOARD
# ==============================

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
REPORTS = ROOT / "reports"

st.set_page_config(
    page_title="ETDR | Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==============================
# PROFESSIONAL DARK THEME
# ==============================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

.stApp {
    background: linear-gradient(135deg, #080d17, #101c30);
    color: #edf4ff;
    font-family: Inter, sans-serif;
}

[data-testid="stSidebar"] {
    background: #0b1424;
    border-right: 1px solid #263a54;
}

.block-container {
    padding-top: 1.5rem;
    max-width: 1600px;
}

.hero {
    padding: 28px;
    border-radius: 20px;
    background: linear-gradient(120deg, #172c48, #0e192a);
    border: 1px solid #294260;
    margin-bottom: 22px;
}

.hero-title {
    font-size: 32px;
    font-weight: 800;
    color: #f5f8ff;
}

.hero-subtitle {
    color: #a9bbd2;
    margin-top: 8px;
}

.metric-card {
    background: linear-gradient(145deg, #152740, #101a2b);
    border: 1px solid #29415e;
    padding: 20px;
    border-radius: 16px;
    min-height: 125px;
}

.metric-label {
    color: #9fb4cc;
    font-size: 13px;
    font-weight: 700;
    text-transform: uppercase;
}

.metric-value {
    font-size: 32px;
    font-weight: 800;
    color: #ffffff;
    margin-top: 10px;
}

.metric-note {
    color: #7f96b1;
    font-size: 12px;
    margin-top: 5px;
}

.stButton > button {
    border-radius: 9px;
    background: #173b5a;
    color: white;
    border: 1px solid #315879;
    font-weight: 700;
}

h1, h2, h3 {
    color: #f5f8ff !important;
}

hr {
    border-color: #263a54;
}
</style>
""", unsafe_allow_html=True)


# ==============================
# LOAD PROJECT DATA
# ==============================

def load_csv(filename):
    path = DATA / filename

    if not path.exists():
        return pd.DataFrame()

    try:
        return pd.read_csv(path)
    except (pd.errors.EmptyDataError, pd.errors.ParserError):
        return pd.DataFrame()


events = load_csv("endpoint_events.csv")
scored = load_csv("scored_events.csv")
alerts = load_csv("security_alerts.csv")
investigations = load_csv("investigation_report.csv")
attack = load_csv("attack_mapping.csv")
incidents = load_csv("correlated_incidents.csv")
intel = load_csv("threat_intelligence.csv")
responses = load_csv("response_actions.csv")
evidence = load_csv("evidence_inventory.csv")


# ==============================
# SIDEBAR NAVIGATION
# ==============================

with st.sidebar:
    st.title("🛡️ ETDR")
    st.caption("SECURITY OPERATIONS CENTER")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Overview",
            "Alert Center",
            "Investigation",
            "ATT&CK Explorer",
            "Threat Intelligence",
            "Response Center",
            "Forensics & Reports"
        ]
    )

    st.divider()
    st.success("DEMO ENVIRONMENT")
    st.caption("Synthetic telemetry")
    st.caption("Offline threat intelligence")
    st.caption("Simulated response only")

    if st.button("↻ Refresh Dashboard", use_container_width=True):
        st.rerun()


# ==============================
# HEADER
# ==============================

st.markdown("""
<div class="hero">
    <div style="color:#54dec9;font-weight:800;letter-spacing:3px">
        SECURITY OPERATIONS CENTER
    </div>
    <div class="hero-title">
        Endpoint Threat Detection & Response
    </div>
    <div class="hero-subtitle">
        Endpoint monitoring • AI anomaly detection • Threat investigation
        • Incident response • Digital forensics
    </div>
</div>
""", unsafe_allow_html=True)


# ==============================
# EMPTY DATA CHECK
# ==============================

if events.empty and alerts.empty:
    st.warning(
        "Project data not found. Run `python run_all.py` "
        "in the VS Code terminal, then refresh this dashboard."
    )
    st.stop()


# ==============================
# METRIC CARD FUNCTION
# ==============================

def metric_card(label, value, note):
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-note">{note}</div>
    </div>
    """, unsafe_allow_html=True)


# ==============================
# OVERVIEW
# ==============================

if page == "Overview":

    st.subheader("Security Overview")

    high_critical = 0
    critical = 0

    if not alerts.empty and "severity" in alerts.columns:
        high_critical = int(
            alerts["severity"].isin(["High", "Critical"]).sum()
        )
        critical = int((alerts["severity"] == "Critical").sum())

    hosts = (
        events["host"].nunique()
        if not events.empty and "host" in events.columns
        else 0
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        metric_card("Endpoint Events", f"{len(events):,}", "Collected records")

    with c2:
        metric_card("Total Alerts", f"{len(alerts):,}", "Generated alerts")

    with c3:
        metric_card("High / Critical", f"{high_critical:,}", f"{critical} critical")

    with c4:
        metric_card("Endpoints", f"{hosts:,}", "Unique hostnames")

    st.write("")

    left, right = st.columns(2)

    with left:
        st.subheader("Alert Severity Distribution")

        if not alerts.empty and "severity" in alerts.columns:
            counts = (
                alerts["severity"]
                .value_counts()
                .rename_axis("Severity")
                .reset_index(name="Count")
            )

            fig = px.pie(
                counts,
                names="Severity",
                values="Count",
                hole=0.65,
                color="Severity",
                color_discrete_map={
                    "Critical": "#ff5268",
                    "High": "#ff9955",
                    "Medium": "#ffd166",
                    "Low": "#35c9a7"
                }
            )

            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#dce8f8"
            )

            st.plotly_chart(fig, use_container_width=True)

        else:
            st.info("No alerts available.")

    with right:
        st.subheader("AI Anomaly Score Distribution")

        if not scored.empty and "anomaly_score" in scored.columns:
            fig = px.histogram(
                scored,
                x="anomaly_score",
                nbins=20,
                color_discrete_sequence=["#42d6c5"]
            )

            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#dce8f8",
                xaxis_title="Relative anomaly score",
                yaxis_title="Event count"
            )

            st.plotly_chart(fig, use_container_width=True)

        else:
            st.info("No anomaly scores available.")

    st.subheader("Priority Alert Queue")

    if not alerts.empty:
        view = alerts.copy()

        if "risk_score" in view.columns:
            view["risk_score"] = pd.to_numeric(
                view["risk_score"], errors="coerce"
            ).fillna(0)

            view = view.sort_values("risk_score", ascending=False)

        st.dataframe(
            view.head(10),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No alerts to display.")


# ==============================
# ALERT CENTER
# ==============================

elif page == "Alert Center":

    st.subheader("🚨 Alert Center")
    st.caption("Filter and prioritize alerts for analyst review.")

    if alerts.empty:
        st.info("No alerts found.")
    else:
        view = alerts.copy()

        c1, c2 = st.columns(2)

        if "severity" in view.columns:
            with c1:
                severity_options = ["Critical", "High", "Medium", "Low"]
                selected = st.multiselect(
                    "Filter by severity",
                    severity_options,
                    default=severity_options
                )

            view = view[view["severity"].isin(selected)]

        if "host" in view.columns:
            with c2:
                host_options = sorted(
                    view["host"].dropna().astype(str).unique()
                )
                selected_hosts = st.multiselect(
                    "Filter by endpoint",
                    host_options,
                    default=host_options
                )

            view = view[view["host"].astype(str).isin(selected_hosts)]

        if "risk_score" in view.columns:
            view = view.sort_values("risk_score", ascending=False)

        st.dataframe(view, use_container_width=True, hide_index=True)


# ==============================
# INVESTIGATION
# ==============================

elif page == "Investigation":

    st.subheader("🔎 Threat Investigation")

    tab1, tab2 = st.tabs(
        ["Process Investigation", "Correlated Incidents"]
    )

    with tab1:
        if investigations.empty:
            st.info("No investigation findings available.")
        else:
            st.dataframe(
                investigations,
                use_container_width=True,
                hide_index=True
            )

            st.warning(
                "Process names and command-line indicators are clues, "
                "not proof of malicious activity."
            )

    with tab2:
        if incidents.empty:
            st.info("No correlated incidents available.")
        else:
            st.dataframe(
                incidents,
                use_container_width=True,
                hide_index=True
            )


# ==============================
# MITRE ATT&CK EXPLORER
# ==============================

elif page == "ATT&CK Explorer":

    st.subheader("🎯 MITRE ATT&CK Explorer")

    if attack.empty:
        st.info("No ATT&CK mappings found.")
    else:
        st.dataframe(
            attack,
            use_container_width=True,
            hide_index=True
        )

        st.info(
            "These are candidate technique mappings generated by "
            "heuristics. Validate them against the event context."
        )


# ==============================
# THREAT INTELLIGENCE
# ==============================

elif page == "Threat Intelligence":

    st.subheader("🌐 Threat Intelligence")

    if intel.empty:
        st.info("No enrichment results found.")
    else:
        st.dataframe(
            intel,
            use_container_width=True,
            hide_index=True
        )

        st.caption(
            "This project uses an offline demonstration feed. "
            "It does not perform external reputation lookups."
        )


# ==============================
# RESPONSE CENTER
# ==============================

elif page == "Response Center":

    st.subheader("🛡️ Incident Response Center")

    st.warning(
        "SIMULATION ONLY: no endpoints, processes, user accounts, "
        "or firewall rules are changed."
    )

    if responses.empty:
        st.info("No response records found.")
    else:
        st.dataframe(
            responses,
            use_container_width=True,
            hide_index=True
        )

    st.markdown("### Recommended analyst workflow")
    st.markdown("""
    1. Validate the alert.
    2. Investigate the endpoint and process ancestry.
    3. Preserve relevant evidence.
    4. Obtain approval before real containment.
    5. Record the action and its outcome.
    """)


# ==============================
# FORENSICS AND REPORTS
# ==============================

elif page == "Forensics & Reports":

    st.subheader("🧾 Digital Forensics & Evidence")

    if evidence.empty:
        st.info("No evidence inventory found.")
    else:
        st.dataframe(
            evidence,
            use_container_width=True,
            hide_index=True
        )

    report_path = REPORTS / "incident_report.md"

    st.subheader("Incident Report")

    if report_path.exists():
        report_text = report_path.read_text(encoding="utf-8")
        st.markdown(report_text)

        st.download_button(
            "⬇ Download Incident Report",
            data=report_text,
            file_name="incident_report.md",
            mime="text/markdown"
        )
    else:
        st.info("Run python run_all.py to generate the report.")


# ==============================
# FOOTER
# ==============================

st.divider()

st.caption(
    "ETDR Educational Prototype | Synthetic data | "
    "Anomaly scores are not probabilities | Response is simulation-only"
)