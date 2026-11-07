import sys
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ddos_sim.traffic_generator import generate_scenario
from ddos_sim.monitor import add_traffic_features
from ddos_sim.detector import detect_attacks
from ddos_sim.mitigation import apply_simulated_mitigation
from ddos_sim.evaluation import calculate_metrics

class PipelineTests(unittest.TestCase):
    def test_pipeline_is_repeatable_and_complete(self):
        raw = generate_scenario("DDoS attack", duration=90, seed=7)
        detected = detect_attacks(add_traffic_features(raw))
        result = apply_simulated_mitigation(detected, 10)
        self.assertEqual(len(result), 90)
        self.assertIn("anomaly_score", result)
        self.assertTrue((result.blocked_requests >= 0).all())
        self.assertTrue((result.allowed_requests + result.blocked_requests == result.requests).all())
        self.assertIn("f1_score", calculate_metrics(result))

    def test_detector_does_not_require_ground_truth(self):
        raw = generate_scenario("Normal traffic", duration=60).drop(columns=["ground_truth_attack"])
        self.assertIn("detected_attack", detect_attacks(add_traffic_features(raw)))

    def test_attack_profiles(self):
        from ddos_sim.traffic_generator import ATTACK_TYPES
        for kind in ATTACK_TYPES:
            df = generate_scenario("DDoS attack", duration=90, seed=11, attack_type=kind)
            self.assertTrue(df.ground_truth_attack.any())
            self.assertEqual(set(df.attack_type), {kind})

    def test_ml_detector(self):
        from ddos_sim.ml_detector import train_and_evaluate, predict_traffic, FEATURES
        model, metrics = train_and_evaluate()
        featured = add_traffic_features(generate_scenario("DDoS attack", duration=60, seed=77, attack_type="UDP flood"))
        predicted = predict_traffic(model, featured)
        self.assertIn("ml_detected_attack", predicted)
        self.assertTrue(predicted.ml_attack_probability.between(0, 1).all())
        self.assertNotIn("ground_truth_attack", FEATURES)
        self.assertGreater(metrics["training_observations"], metrics["testing_observations"])

if __name__ == "__main__":
    unittest.main()
