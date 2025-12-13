# Phishing URL Detector - ML Model & Browser Extension

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![CatBoost](https://img.shields.io/badge/CatBoost-1.2%2B-orange)
![ONNX](https://img.shields.io/badge/ONNX-Runtime-lightgrey)

## Описание
Мощная система для автоматического определения фишинговых URL-адресов. Проект включает в себя:
1. **Python Backend**: Полный цикл обучения модели (CatBoost) на объединенном датасете (~800k URL) с экспортом в ONNX.
2. **Browser Extension**: Расширение для Chrome/Edge, которое использует обученную модель локально (через WebAssembly) для проверки сайтов в реальном времени без передачи данных на сервер.

## Основные возможности
- **Точность**: ~96.2% (Accuracy), ROC AUC ~0.993
- **Приватность**: Проверка URL происходит **локально** в браузере пользователя.
- **Данные**: 800k+ URL (сбалансированная выборка фишинга и легитимных сайтов).
- **Признаки**: 70+ (структурные, лексические, энтропия, TLD).
- **Скорость**: Инференс < 10ms на URL благодаря ONNX Runtime Web.
- **Черный список**: 240k+ известных фишинговых URL из JPCERT/CC (2020-2025) для мгновенной проверки.

## Структура проекта
```
phishing-detector/
├── src/                 # Python исходники для обучения
│   ├── training/        # Скрипты обучения (CatBoost, Optuna, K-Fold)
│   ├── data/            # Загрузка данных и Feature Extractor
│   ├── inference/       # Python инференс
│   └── ...
├── extension/           # Браузерное расширение (JS)
│   ├── model/           # Экспортированная ONNX модель
│   ├── js/              # Логика (Feature Extractor порт, Background worker)
│   ├── popup/           # UI попапа
│   ├── assets/          # Черный список JPCERT/CC (phishurl-list.csv)
│   └── manifest.json    # Конфиг расширения
├── models/              # Сохраненные модели
└── ...
```

## Установка и запуск

### 1. Обучение модели (Python)
Если вы хотите переобучить модель самостоятельно:

1. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```
2. Запустите обучение (автоматически скачает данные и найдет GPU):
   ```bash
   python src/training/train.py
   ```
   *Это создаст файл `models/model_latest.onnx`.*

### 2. Установка расширения в Браузер
Чтобы использовать защиту в браузере:

**Вариант 1: Установка из репозитория (рекомендуется)**
1. Скачайте репозиторий:
   ```bash
   git clone https://github.com/phantom2059/URL_detector.git
   cd URL_detector
   ```
   Или скачайте ZIP-архив с GitHub и распакуйте его.

2. Откройте Chrome/Edge и перейдите по адресу `chrome://extensions/`.
3. Включите **"Режим разработчика"** (Developer mode) в правом верхнем углу.
4. Нажмите **"Загрузить распакованное расширение"** (Load unpacked).
5. Выберите папку `extension` из скачанного репозитория.

**Вариант 2: Обновление модели (если переобучали)**
Если вы переобучили модель, скопируйте новую модель в папку расширения:
```bash
copy models/model_latest.onnx extension/model/model.onnx
```

Теперь при посещении подозрительных сайтов иконка расширения станет красной, и вы получите уведомление!

## Датасеты
Проект использует объединенные датасеты для обучения модели:
1. **[ealvaradob/phishing-dataset](https://huggingface.co/datasets/ealvaradob/phishing-dataset)** (Hugging Face) - основной датасет фишинговых и легитимных URL.
2. **[Phishing and Legitimate URLs](https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls)** (Kaggle) - дополнительный датасет для увеличения объема данных.

**Черный список для расширения:**
- **[JPCERT/CC PhishURL List](https://github.com/JPCERTCC/phishurl-list)** - объединенный черный список из 240,758 уникальных фишинговых URL за период 2020-2025, оптимизированный для быстрой проверки в расширении.

## Технические детали
*   **Feature Extraction**: Логика извлечения признаков полностью портирована с Python на JavaScript (`extension/js/feature_extractor.js`), чтобы гарантировать идентичность векторов признаков.
*   **ONNX Runtime Web**: Используется WASM-бэкенд для запуска модели CatBoost прямо в браузере.
*   **Whitelist**: Поддержка локального белого списка через `chrome.storage`.
*   **Blacklist**: Локальная проверка по черному списку JPCERT/CC (240k+ URL) перед запуском ML-модели для максимальной скорости.

## Метрики модели
На отложенной выборке (20%):
- **Accuracy**: 96.21%
- **Precision**: 95.66%
- **Recall**: 97.23%
- **F1 Score**: 96.44%
- **ROC AUC**: 0.9935
