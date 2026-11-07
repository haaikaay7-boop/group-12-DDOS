"""Offline ML detector trained and evaluated on independent synthetic scenarios."""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from .traffic_generator import generate_scenario, ATTACK_TYPES
from .monitor import add_traffic_features
FEATURES = ["requests","unique_sources","avg_packet_bytes","failed_ratio","syn_ratio","udp_ratio","http_ratio","slow_request_ratio","avg_request_duration_ms","traffic_ratio","robust_z_score","source_density","anomaly_score"]

def _build_dataset(seeds, duration=120):
    frames=[]
    for seed in seeds:
        frames += [generate_scenario("Normal traffic",duration,40,500,seed), generate_scenario("Legitimate flash crowd",duration,40,500,seed+10000)]
        for i, kind in enumerate(ATTACK_TYPES):
            frames += [generate_scenario("DDoS attack",duration,40,500,seed+20000+i,kind), generate_scenario("Mixed traffic",duration,40,500,seed+30000+i,kind)]
    return pd.concat([add_traffic_features(f) for f in frames],ignore_index=True)

def train_and_evaluate(seed=2026):
    train=_build_dataset(range(10,22)); test=_build_dataset(range(100,105))
    model=RandomForestClassifier(n_estimators=160,max_depth=12,min_samples_leaf=2,class_weight="balanced",random_state=seed,n_jobs=-1)
    model.fit(train[FEATURES],train["ground_truth_attack"].astype(int)); truth=test["ground_truth_attack"].astype(int).to_numpy(); pred=model.predict(test[FEATURES])
    tn,fp,fn,tp=confusion_matrix(truth,pred,labels=[0,1]).ravel()
    metrics={"accuracy":float(accuracy_score(truth,pred)),"precision":float(precision_score(truth,pred,zero_division=0)),"recall":float(recall_score(truth,pred,zero_division=0)),"f1_score":float(f1_score(truth,pred,zero_division=0)),"false_positive_rate":float(fp/(fp+tn)) if fp+tn else 0.0,"true_positives":int(tp),"true_negatives":int(tn),"false_positives":int(fp),"false_negatives":int(fn),"training_observations":len(train),"testing_observations":len(test),"features":FEATURES}
    return model,metrics

def predict_traffic(model,df):
    out=df.copy(); out["ml_detected_attack"]=model.predict(out[FEATURES]).astype(bool); out["ml_attack_probability"]=model.predict_proba(out[FEATURES])[:,1].round(4)
    out["ml_detection_reason"]=np.where(out["ml_detected_attack"],"ML model classified this interval as suspicious","ML model classified this interval as normal")
    return out
