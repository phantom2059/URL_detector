# URL Detector

**Phishing URL detection system — CatBoost ML model with a privacy-first Chrome extension**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![CatBoost](https://img.shields.io/badge/CatBoost-FFCC00?style=flat-square&logoColor=black)
![ONNX](https://img.shields.io/badge/ONNX_Runtime-005CED?style=flat-square&logo=onnx&logoColor=white)
![Chrome](https://img.shields.io/badge/Chrome_Extension-v1.2-4285F4?style=flat-square&logo=googlechrome&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

---

## Overview

End-to-end phishing detection pipeline: from training a gradient boosting classifier on a combined 800k+ URL dataset to running real-time inference locally in the browser through ONNX Runtime Web (WASM backend). The entire classification happens on the client side — no data leaves the user’s machine.

The project has two independent parts:

- **Python training pipeline** — data loading from multiple sources, feature engineering (70+ features), hyperparameter search with Optuna, K-Fold cross-validation, CatBoost model training, and ONNX export.
- **Chrome/Edge extension** — loads the exported ONNX model via WebAssembly, extracts the same feature set in JavaScript, and classifies every visited URL in real time. Ships with a curated whitelist (Tranco Top 10K most reliable domains) and a blacklist (JPCERT/CC phishing feed, 240k+ entries from 2020–2025).

---

## Model performance

Evaluated on a 20% holdout split:

| Metric | Value |
|--------|-------|
| Accuracy | 96.21% |
| Precision | 95.66% |
| Recall | 97.23% |
| F1 Score | 96.44% |
| ROC AUC | 0.9935 |

Inference time: <10 ms per URL (ONNX Runtime Web, WASM backend).

---

## Feature engineering

The model uses 70+ features extracted from URL structure alone (no page content fetching required):

- **Structural** — URL length, path depth, number of subdomains, query parameter count, fragment presence
- **Lexical** — special character ratios (`@`, `-`, `.`, `//`), digit-to-letter ratio, presence of IP address
- **Statistical** — Shannon entropy of the full URL, hostname, and path components
- **Domain-based** — TLD category, domain age signals, registration length indicators
- **Protocol & security** — HTTPS usage, port presence, redirect patterns

All features are identically implemented in both Python (`src/data/`) and JavaScript (`extension/js/`) to ensure training-inference parity.

---

## Datasets

Training data merges two public sources into a balanced ~800k URL corpus:

- [ealvaradob/phishing-dataset](https://huggingface.co/datasets/ealvaradob/phishing-dataset) (Hugging Face) — primary dataset
- [Phishing and Legitimate URLs](https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls) (Kaggle) — supplementary dataset

Extension runtime lists:

- [Tranco Top 10K](https://tranco-list.eu/) — whitelist of 10,000 most visited and trusted domains
- [JPCERT/CC PhishURL List](https://github.com/JPCERTCC/phishurl-list) — blacklist, 240k+ confirmed phishing URLs

---

## Project structure

```
├── src/
│   ├── training/        # CatBoost training, Optuna HPO, K-Fold CV
│   ├── data/            # Dataset loaders, feature extraction (Python)
│   ├── inference/       # Python-side inference scripts
│   ├── config/          # Training and model configuration
│   └── utils/           # Preprocessing, evaluation helpers
├── extension/
│   ├── js/              # Feature extractor (JS port), background service worker
│   ├── popup/           # Extension popup UI
│   ├── assets/          # Tranco whitelist, JPCERT blacklist data
│   ├── lib/             # ONNX Runtime Web (WASM)
│   ├── images/          # Extension icons
│   └── manifest.json    # Chrome Manifest V3
├── catboost_info/       # CatBoost training logs
├── requirements.txt
├── test_urls.txt        # Sample URLs for quick testing
└── LICENSE
```

---

## Quick start

### Training the model

```bash
pip install -r requirements.txt
python src/training/train.py
```

### Installing the extension

```bash
git clone https://github.com/phantom2059/URL_detector.git
```

1. Open `chrome://extensions/` (or `edge://extensions/`)
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `extension/` folder

The extension will immediately start checking URLs on every page navigation.

---

## Extension features

- **Real-time classification** — every page load triggers local ML inference (<10 ms)
- **Dynamic badge icon** — color-coded status indicator: green (safe), red (phishing), gray (whitelisted)
- **Session statistics** — counter of checked sites and blocked threats in the popup
- **Tranco whitelist** — top 10K trusted domains are automatically skipped
- **JPCERT blacklist** — 240k+ known phishing URLs are instantly flagged without model inference
- **User whitelist** — manually trust domains with instant activation
- **Dark / light theme** — adapts to browser preferences

---

## Changelog

**v1.2** — Tranco Top 10K whitelist, dynamic badge icon with status colors, session statistics, performance optimizations, instant whitelist updates.

**v1.1** — JPCERT/CC blacklist integration, dark/light theme support, user whitelist management.

**v1.0** — Initial release. CatBoost model, ONNX export, basic extension functionality.

---

## License

MIT
