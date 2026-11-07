"""Aggregate rate-limiting simulation. Does not use attack labels to make decisions."""
def apply_simulated_mitigation(df, per_source_limit=10):
    out = df.copy(); allowed, blocked = [], []
    for _, row in out.iterrows():
        capacity = max(0, int(row["unique_sources"]) * int(per_source_limit))
        permitted = min(int(row["requests"]), capacity) if bool(row["detected_attack"]) else int(row["requests"])
        allowed.append(permitted); blocked.append(int(row["requests"]) - permitted)
    out["allowed_requests"] = allowed; out["blocked_requests"] = blocked
    out["legitimate_served"] = out[["legitimate_requests", "allowed_requests"]].min(axis=1).astype(int)
    out["attack_allowed_estimate"] = (out["allowed_requests"] - out["legitimate_served"]).clip(lower=0).astype(int)
    out["attack_blocked_estimate"] = (out["attack_requests"] - out["attack_allowed_estimate"]).clip(lower=0).astype(int)
    return out
