# URL Detector

**Система детекции фишинговых URL — CatBoost ML-модель + браузерное расширение с приватностью**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![CatBoost](https://img.shields.io/badge/CatBoost-FFCC00?style=flat-square&logoColor=black)
![ONNX](https://img.shields.io/badge/ONNX_Runtime-005CED?style=flat-square&logo=onnx&logoColor=white)
![Chrome](https://img.shields.io/badge/Chrome_Extension-v1.2-4285F4?style=flat-square&logo=googlechrome&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

---

## Overview

End-to-end пайплайн для детекции фишинговых URL: от обучения градиентного бустинга на 800k+ URL до реал-тайм инференса локально в браузере через ONNX Runtime Web (WASM). Вся классификация происходит на клиенте — никакие данные не покидают машину пользователя.

Проект состоит из двух независимых частей:

- **Python training pipeline** — загрузка данных из нескольких источников, feature engineering (70+ признаков), подбор гиперпараметров через Optuna, K-Fold кросс-валидация, обучение CatBoost и экспорт в ONNX.
- **Chrome/Edge extension** — загружает ONNX-модель через WebAssembly, извлекает тот же набор признаков на JavaScript и классифицирует каждый URL в реальном времени. Включает белый список (Tranco Top 10K) и чёрный список (JPCERT/CC, 240k+ записей за 2020–2025).

---

## Model performance

Метрики на отложенной выборке (20% holdout):

| Metric | Value |
|--------|-------|
| Accuracy | 96.21% |
| Precision | 95.66% |
| Recall | 97.23% |
| F1 Score | 96.44% |
| ROC AUC | 0.9935 |

Время инференса: <10 ms на URL (ONNX Runtime Web, WASM backend).

---

## Feature engineering

Модель использует 70+ признаков, извлекаемых только из структуры URL (без загрузки содержимого страниц):

- **Structural** — длина URL, глубина пути, количество субдоменов, query-параметры, фрагменты
- **Lexical** — соотношения спецсимволов (`@`, `-`, `.`, `//`), соотношение цифр/букв, наличие IP-адреса
- **Statistical** — энтропия Шеннона для URL, hostname и path
- **Domain-based** — категория TLD, сигналы возраста домена, длительность регистрации
- **Protocol & security** — использование HTTPS, наличие порта, паттерны редиректов

Все признаки идентично реализованы на Python (`src/data/`) и JavaScript (`extension/js/`) для обеспечения training-inference parity.

---

## Datasets

Обучающие данные объединяют два публичных источника в сбалансированный корпус ~800k URL:

- [ealvaradob/phishing-dataset](https://huggingface.co/datasets/ealvaradob/phishing-dataset) (Hugging Face) — основной датасет
- [Phishing and Legitimate URLs](https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls) (Kaggle) — дополнительный датасет

Списки для расширения:

- [Tranco Top 10K](https://tranco-list.eu/) — белый список 10 000 самых надёжных доменов
- [JPCERT/CC PhishURL List](https://github.com/JPCERTCC/phishurl-list) — чёрный список, 240k+ подтверждённых фишинговых URL

---

## Project structure

```
├── src/
│   ├── training/        # Обучение CatBoost, Optuna HPO, K-Fold CV
│   ├── data/            # Загрузчики данных, извлечение признаков (Python)
│   ├── inference/       # Инференс на Python
│   ├── config/          # Конфигурация
│   └── utils/           # Вспомогательные функции
├── extension/
│   ├── js/              # Feature extractor (JS-порт), background service worker
│   ├── popup/           # UI расширения
│   ├── assets/          # Tranco whitelist, JPCERT blacklist
│   ├── lib/             # ONNX Runtime Web (WASM)
│   ├── images/          # Иконки расширения
│   └── manifest.json    # Chrome Manifest V3
├── catboost_info/       # Логи обучения CatBoost
├── requirements.txt
├── test_urls.txt        # Тестовые URL для быстрой проверки
└── LICENSE
```

---

## Quick start

### Обучение модели

```bash
pip install -r requirements.txt
python src/training/train.py
```

### Установка расширения

```bash
git clone https://github.com/phantom2059/URL_detector.git
```

1. Откройте `chrome://extensions/` (или `edge://extensions/`)
2. Включите **Режим разработчика**
3. Нажмите **Загрузить распакованное расширение** и выберите папку `extension/`

Расширение сразу начнёт проверять URL при каждом переходе.

---

## Extension features

- **Real-time classification** — каждый переход запускает локальный ML-инференс (<10 ms)
- **Dynamic badge icon** — цветовой индикатор статуса: зелёный (безопасно), красный (фишинг), серый (whitelist)
- **Session statistics** — счётчик проверенных сайтов и заблокированных угроз
- **Tranco whitelist** — топ-10K доверенных доменов пропускаются автоматически
- **JPCERT blacklist** — 240k+ известных фишинговых URL блокируются без инференса
- **User whitelist** — ручное добавление доменов с мгновенной активацией
- **Dark / light theme** — адаптация под настройки браузера

---

## Changelog

**v1.2** — Tranco Top 10K whitelist, динамическая иконка со статусом, статистика проверок, оптимизация производительности.

**v1.1** — Интеграция чёрного списка JPCERT/CC, тёмная/светлая тема, управление белым списком.

**v1.0** — Первый релиз. Модель CatBoost, экспорт ONNX, базовый функционал расширения.

---

## License

MIT
