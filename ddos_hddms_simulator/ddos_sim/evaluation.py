"""Evaluate detection decisions against synthetic labels, not during detection."""
def calculate_metrics(df):
    actual = df["ground_truth_attack"].astype(bool)
    predicted = df["detected_attack"].astype(bool)
    tp = int((actual & predicted).sum()); tn = int((~actual & ~predicted).sum())
    fp = int((~actual & predicted).sum()); fn = int((actual & ~predicted).sum())
    def ratio(n, d): return n / d if d else 0.0
    precision = ratio(tp, tp + fp); recall = ratio(tp, tp + fn)
    return {"accuracy": ratio(tp + tn, len(df)), "precision": precision, "recall": recall,
            "f1_score": ratio(2 * precision * recall, precision + recall),
            "false_positive_rate": ratio(fp, fp + tn), "true_positives": tp,
            "true_negatives": tn, "false_positives": fp, "false_negatives": fn}
