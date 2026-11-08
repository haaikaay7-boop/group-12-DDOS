"""HDDMS dashboard — safe synthetic DDoS detection and mitigation lab."""
import sys
from pathlib import Path
import pandas as pd
import streamlit as st
import plotly.express as px

ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from ddos_sim.auth import require_login
from ddos_sim.traffic_generator import generate_scenario, ATTACK_TYPES
from ddos_sim.monitor import add_traffic_features
from ddos_sim.detector import detect_attacks
from ddos_sim.mitigation import apply_simulated_mitigation
from ddos_sim.evaluation import calculate_metrics
from ddos_sim.ml_detector import train_and_evaluate, predict_traffic

st.set_page_config(page_title="HDDMS | DDoS Simulator", page_icon="🛡️", layout="wide")

@st.cache_resource
def load_ml_model():
    return train_and_evaluate()

if not require_login():
    st.stop()

st.title("🛡️ Hybrid DDoS Detection & Mitigation Simulator")
st.caption("HDDMS • Academic cyber-security lab • Synthetic traffic only; no packets are sent.")

with st.sidebar:
    st.header("Simulation controls")
    scenario = st.selectbox("Traffic scenario", ["Normal traffic", "DDoS attack", "Legitimate flash crowd", "Mixed traffic"])
    attack_type = st.selectbox("Attack category", ATTACK_TYPES)
    duration = st.slider("Duration (seconds)", 30, 300, 120, 10)
    baseline = st.slider("Normal requests / second", 5, 200, 40, 5)
    intensity = st.slider("Synthetic attack requests / second", 50, 2000, 500, 50)
    sensitivity = st.slider("Anomaly sensitivity", 1.5, 5.0, 2.5, 0.1)
    threshold_multiplier = st.slider("Baseline threshold multiplier", 1.5, 10.0, 3.0, 0.5)
    mitigation_on = st.toggle("Enable simulated rate limiting", True)
    source_limit = st.slider("Quota per simulated source", 1, 50, 10)
    seed = st.number_input("Random seed", min_value=0, max_value=999999, value=42, step=1)
    run = st.button("▶ Run / refresh simulation", type="primary", use_container_width=True)

if run or "simulation_df" not in st.session_state:
    raw = generate_scenario(scenario, duration, baseline, intensity, int(seed), attack_type)
    monitored = add_traffic_features(raw)
    detected = detect_attacks(monitored, threshold_multiplier, sensitivity)
    ml_model, ml_training_metrics = load_ml_model()
    detected = predict_traffic(ml_model, detected)
    result = apply_simulated_mitigation(detected, source_limit) if mitigation_on else detected.copy()
    if not mitigation_on:
        result["allowed_requests"] = result["requests"]
        result["blocked_requests"] = 0
        result["legitimate_served"] = result["legitimate_requests"]
        result["attack_allowed_estimate"] = result["attack_requests"]
        result["attack_blocked_estimate"] = 0
    st.session_state["simulation_df"] = result
    st.session_state["scenario"] = scenario
    st.session_state["attack_type"] = attack_type
    st.session_state["mitigation_enabled"] = mitigation_on
    st.session_state["ml_training_metrics"] = ml_training_metrics

df = st.session_state["simulation_df"]
metrics = calculate_metrics(df)
# Match the deterministic attack window used by generate_scenario().
sim_duration = len(df)
window_start = max(5, sim_duration // 3)
window_end = min(sim_duration - 3, window_start + max(10, sim_duration // 3))
selected_scenario = st.session_state["scenario"]

st.subheader("Simulation timeline")
if selected_scenario in ("DDoS attack", "Mixed traffic"):
    attack_seconds = int(df["attack_requests"].gt(0).sum())
    t1, t2, t3 = st.columns(3)
    t1.metric("Attack begins", f"{window_start}s")
    t2.metric("Attack ends", f"{window_end - 1}s")
    t3.metric("Attack duration", f"{window_end - window_start}s")
    st.info(
        f"Scheduled {st.session_state['attack_type']} window: seconds "
        f"{window_start}–{window_end - 1}. The event log below contains the "
        "whole generated run; use the attack-window filter to jump to these rows."
    )
    phases = pd.DataFrame([
        {"phase": "Normal traffic", "start": 0, "length": window_start},
        {"phase": "Simulated attack", "start": window_start, "length": window_end - window_start},
        {"phase": "Recovery / normal traffic", "start": window_end, "length": sim_duration - window_end},
    ])
    timeline = px.bar(
        phases, x="length", y="phase", orientation="h", base="start",
        text="length", title="When each phase occurs (seconds)",
        labels={"length": "Duration (seconds)", "phase": ""},
    )
    timeline.update_layout(showlegend=False, xaxis_range=[0, sim_duration], yaxis_title="")
    st.plotly_chart(timeline, use_container_width=True)
    if attack_seconds:
        st.success(f"Generated {int(df['attack_requests'].sum()):,} simulated illegitimate requests across {attack_seconds} seconds.")
    else:
        st.warning("No attack requests appear in this run. Check that the selected scenario is DDoS attack or Mixed traffic, then rerun.")
elif selected_scenario == "Legitimate flash crowd":
    st.info(f"Legitimate flash crowd is scheduled from second {window_start} to {window_end - 1}. This scenario intentionally has zero attack_requests.")
else:
    st.success("Normal-traffic scenario selected. No illegitimate requests are scheduled.")

st.subheader(f"Scenario: {selected_scenario}")
if df["detected_attack"].any():
    st.warning(f"Suspicious activity detected in {int(df['detected_attack'].sum())} of {len(df)} observed seconds.")
else:
    st.success("No suspicious periods were detected with the current settings.")

cols = st.columns(5)
for col, label, value in zip(cols, ["Total requests", "Simulated illegitimate requests", "Flagged seconds", "Requests rate-limited", "Legitimate requests served"],
    [int(df.requests.sum()), int(df.attack_requests.sum()), int(df.detected_attack.sum()), int(df.blocked_requests.sum()), int(df.legitimate_served.sum())]):
    col.metric(label, f"{value:,}")

left, right = st.columns(2)
with left:
    st.subheader("1. Traffic monitoring")
    traffic = df.melt(id_vars=["second"], value_vars=["legitimate_requests", "attack_requests"], var_name="traffic_type", value_name="traffic_requests")
    traffic["traffic_type"] = traffic["traffic_type"].map({"legitimate_requests": "Legitimate traffic", "attack_requests": "Simulated illegitimate traffic"})
    st.plotly_chart(px.area(traffic, x="second", y="traffic_requests", color="traffic_type"), use_container_width=True)
with right:
    st.subheader("2. Detection decisions")
    plot = df.assign(decision=df.detected_attack.map({True:"Flagged", False:"Not flagged"}))
    st.plotly_chart(px.scatter(plot, x="second", y="requests", color="decision", hover_data=["traffic_ratio","robust_z_score","anomaly_score","detection_reason"]), use_container_width=True)

st.subheader("3. Detection signals")
signals = df.melt(id_vars=["second"], value_vars=["traffic_ratio","anomaly_score"], var_name="signal", value_name="value")
st.plotly_chart(px.line(signals, x="second", y="value", color="signal"), use_container_width=True)

st.subheader("4. Mitigation impact")
st.write("Simulated mitigation: **ON**" if st.session_state["mitigation_enabled"] else "Simulated mitigation: **OFF**")
st.plotly_chart(px.line(df, x="second", y=["requests","allowed_requests"]), use_container_width=True)

st.subheader("5. Detection performance")
metric_cols = st.columns(5)
for col, label, key in zip(metric_cols, ["Accuracy","Precision","Recall","F1-score","False-positive rate"], ["accuracy","precision","recall","f1_score","false_positive_rate"]):
    col.metric(label, f"{metrics[key]:.1%}")
st.subheader("6. Machine-learning detection")
ml = st.session_state.get("ml_training_metrics", {})
a, b = st.columns(2)
a.metric("ML-flagged seconds", f"{int(df.ml_detected_attack.sum()):,}")
a.metric("Mean ML attack probability", f"{df.ml_attack_probability.mean():.1%}")
b.metric("ML test-set F1-score", f"{ml.get('f1_score', 0):.1%}")
b.metric("Independent test observations", f"{ml.get('testing_observations', 0):,}")
st.subheader("7. Simulation event log")
event_log = df.copy()
if selected_scenario in ("DDoS attack", "Mixed traffic"):
    event_log["traffic_phase"] = "Normal traffic"
    event_log.loc[event_log["second"].between(window_start, window_end - 1), "traffic_phase"] = "Simulated attack"
    event_log.loc[event_log["second"] >= window_end, "traffic_phase"] = "Recovery / normal traffic"
elif selected_scenario == "Legitimate flash crowd":
    event_log["traffic_phase"] = "Normal traffic"
    event_log.loc[event_log["second"].between(window_start, window_end - 1), "traffic_phase"] = "Legitimate flash crowd"
else:
    event_log["traffic_phase"] = "Normal traffic"
event_filter = st.selectbox(
    "Filter event log",
    ["All seconds", "Attack window only", "Normal / recovery only"],
)
if event_filter == "Attack window only":
    event_log = event_log[event_log["traffic_phase"] == "Simulated attack"]
elif event_filter == "Normal / recovery only":
    event_log = event_log[event_log["traffic_phase"] != "Simulated attack"]
st.caption(f"Showing {len(event_log):,} of {len(df):,} simulated seconds.")
st.dataframe(event_log, use_container_width=True, height=360)
st.download_button("⬇ Download results (CSV)", df.to_csv(index=False).encode("utf-8"), "hddms_results.csv", "text/csv")
with st.expander("Methodology and limitations"):
    st.markdown("""
    - Traffic is aggregate and synthetic; no network packets are sent.
    - Monitoring computes a lagged rolling baseline, robust deviation and anomaly score.
    - Detection uses observable features and does not use synthetic ground-truth labels.
    - Mitigation demonstrates aggregate rate limiting, not a production firewall.
    - ML training/testing uses separate synthetic scenario seeds; results do not establish real-world accuracy.
    - A real deployment requires representative, independently labelled network data and external validation.
    """)
