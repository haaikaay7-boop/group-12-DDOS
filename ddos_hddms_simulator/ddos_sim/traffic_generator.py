"""Generate safe, synthetic traffic records for an offline DDoS lab."""
import numpy as np
import pandas as pd
ATTACK_TYPES = ["SYN flood", "UDP flood", "HTTP flood", "Slow-request attack", "Generic volumetric"]

def generate_scenario(scenario, duration=120, baseline_rps=40, attack_rps=500, seed=42, attack_type="Generic volumetric"):
    if attack_type not in ATTACK_TYPES: raise ValueError(f"Unknown attack type: {attack_type}")
    rng = np.random.default_rng(seed); seconds = np.arange(duration)
    start = max(5, duration // 3); end = min(duration - 3, start + max(10, duration // 3))
    legitimate = rng.poisson(baseline_rps, duration); attack = np.zeros(duration, dtype=int)
    if scenario in ("DDoS attack", "Mixed traffic"):
        attack[start:end] = rng.poisson(attack_rps, end - start)
    elif scenario == "Legitimate flash crowd": legitimate[start:end] = rng.poisson(baseline_rps * 5, end - start)
    elif scenario != "Normal traffic": raise ValueError(f"Unknown scenario: {scenario}")
    if scenario == "Mixed traffic": legitimate[start:end] = rng.poisson(baseline_rps * 2, end - start)
    active = attack > 0; requests = legitimate + attack
    sources = np.where(active, rng.integers(80, 250, duration), rng.integers(5, 35, duration))
    packet = np.where(active, rng.normal(450, 90, duration), rng.normal(800, 150, duration)).clip(64, 1500)
    failed = np.where(active, rng.uniform(.15, .55, duration), rng.uniform(0, .08, duration))
    syn = np.zeros(duration); udp = np.zeros(duration); http = np.zeros(duration); slow = np.zeros(duration)
    duration_ms = rng.normal(180, 45, duration).clip(30, 500)
    if attack_type == "SYN flood": syn[active] = rng.uniform(.70, .98, active.sum()); packet[active] = rng.normal(70, 12, active.sum()).clip(40, 120)
    elif attack_type == "UDP flood": udp[active] = rng.uniform(.75, .99, active.sum()); packet[active] = rng.normal(1100, 180, active.sum()).clip(300, 1500)
    elif attack_type == "HTTP flood": http[active] = rng.uniform(.75, .99, active.sum()); failed[active] = rng.uniform(.25, .70, active.sum()); packet[active] = rng.normal(950, 180, active.sum()).clip(200, 1500)
    elif attack_type == "Slow-request attack":
        slow[active] = rng.uniform(.65, .95, active.sum()); duration_ms[active] = rng.normal(12000, 2500, active.sum()).clip(3000, 30000)
        attack[active] = rng.poisson(max(5, attack_rps * .18), active.sum()); requests = legitimate + attack
    else:
        syn[active] = rng.uniform(.15, .35, active.sum()); udp[active] = rng.uniform(.15, .35, active.sum()); http[active] = rng.uniform(.15, .35, active.sum())
    return pd.DataFrame({"second":seconds,"legitimate_requests":legitimate,"attack_requests":attack,"requests":requests,"unique_sources":sources,"avg_packet_bytes":packet.round(1),"failed_ratio":failed.round(3),"syn_ratio":syn.round(3),"udp_ratio":udp.round(3),"http_ratio":http.round(3),"slow_request_ratio":slow.round(3),"avg_request_duration_ms":duration_ms.round(1),"attack_type":attack_type,"ground_truth_attack":active})
