# Third-Party Notice

## Packet_analyzer

The C++ DPI engine in `engine/` is derived from:

- https://github.com/perryvegehan/Packet_analyzer
- Author: perryvegehan

As of 2026-10-20, the upstream repository does **not** declare a license. The
upstream code is retained here for educational and portfolio purposes. The MIT
license in `LICENSE` applies only to original Cypher code and does not grant
rights to upstream-derived files.

Before redistributing this project commercially or using upstream-derived code
in a production product, obtain permission from the upstream author or replace
the affected files with a clean-room implementation.

## Python and ML dependencies

This project uses open-source Python packages including FastAPI, Uvicorn,
NumPy, pandas, scikit-learn, joblib, and python-dotenv. Their licenses are
governed by their respective projects.

## Model artifacts

`server/ml/threat_classifier.pkl` and `server/ml/anomaly_detector.pkl` are
local inference artifacts. Their original training dataset and training script
are not included in this repository. See `server/ml/README.md`.
