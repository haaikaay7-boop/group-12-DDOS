"""Traffic feature engineering; uses observable features, never ground-truth labels."""
import pandas as pd

def add_traffic_features(df, window=10):
    out = df.copy(); prior = out["requests"].shift(1)
    baseline = prior.rolling(window=window, min_periods=3).median()
    fallback = out["requests"].expanding(min_periods=1).median().shift(1)
    baseline = baseline.fillna(fallback).fillna(out["requests"].median()).clip(lower=1)
    mad = (prior - baseline).abs().rolling(window=window, min_periods=3).median()
    robust_sigma = (1.4826 * mad.fillna(1)).clip(lower=1)
    out["rolling_baseline"] = baseline.round(2)
    out["robust_z_score"] = ((out["requests"] - baseline) / robust_sigma).clip(lower=0).round(2)
    out["traffic_ratio"] = (out["requests"] / baseline).round(2)
    out["requests_change"] = out["requests"].diff().fillna(0)
    out["source_density"] = (out["unique_sources"] / out["requests"].clip(lower=1)).round(3)
    volume_signal = (out["traffic_ratio"] / 5).clip(0, 1); source_signal = (out["unique_sources"] / 250).clip(0, 1)
    failure_signal = out["failed_ratio"].clip(0, 1); z_signal = (out["robust_z_score"] / 8).clip(0, 1)
    out["anomaly_score"] = (0.35 * volume_signal + 0.25 * source_signal + 0.15 * failure_signal + 0.25 * z_signal).clip(0, 1).round(3)
    return out
