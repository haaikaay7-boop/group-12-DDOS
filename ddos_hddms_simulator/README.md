# HDDMS DDoS Simulator

A modular educational web simulation for generating benign synthetic network traffic, detecting DDoS-like anomalies, evaluating detection performance, and demonstrating mitigation workflows. This project is intended for controlled learning and defensive testing only.

## Features
- Synthetic traffic generation for normal and attack-like traffic patterns
- Rule-based and machine-learning-assisted anomaly detection
- Monitoring and visualization through Streamlit
- Mitigation simulation and evaluation metrics
- Authentication helpers and configurable settings

## Setup

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Tests

```bash
pytest -q
```

## Project layout

```text
ddos_hddms_simulator/
├── app.py
├── requirements.txt
├── ddos_sim/
│   ├── auth.py
│   ├── config.py
│   ├── detector.py
│   ├── evaluation.py
│   ├── mitigation.py
│   ├── ml_detector.py
│   ├── monitor.py
│   └── traffic_generator.py
└── tests/
    └── test_pipeline.py
```

## Safety
The simulator generates synthetic traffic locally. Do not adapt it to send traffic to systems you do not own or have explicit permission to test. Use the detection and mitigation components for defensive education in an isolated environment.
