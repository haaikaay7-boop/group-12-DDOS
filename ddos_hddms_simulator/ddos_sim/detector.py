"""Hybrid detection using observable traffic features only."""

def detect_attacks(df, threshold_multiplier=3.0, z_sensitivity=2.5):
    out = df.copy()
    warmup = max(5, min(20, len(out) // 5))
    reference = float(out["requests"].iloc[:warmup].median())
    threshold = max(reference * threshold_multiplier, reference + z_sensitivity * max(1.0, reference ** 0.5))
    out["traffic_threshold"] = round(threshold, 2)
    out["threshold_flag"] = out["requests"] > threshold
    out["anomaly_flag"] = (out["anomaly_score"] >= 0.55) & (out["robust_z_score"] >= z_sensitivity) & (out["unique_sources"] >= 40)
    out["detected_attack"] = out["threshold_flag"] | out["anomaly_flag"]
    def reason(row):
        reasons = []
        if row["threshold_flag"]: reasons.append("Request rate exceeded baseline threshold")
        if row["anomaly_flag"]: reasons.append("Combined traffic anomaly (rate, sources, failures)")
        return "; ".join(reasons) if reasons else "No suspicious pattern"
    out["detection_reason"] = out.apply(reason, axis=1)
    return out
