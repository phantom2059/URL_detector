# Phishing URL Detector - ML Model & Browser Extension

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![CatBoost](https://img.shields.io/badge/CatBoost-1.2%2B-orange)
![ONNX](https://img.shields.io/badge/ONNX-Runtime-lightgrey)
![Version](https://img.shields.io/badge/Extension-v1.2-green)

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
- **Белый список**: Tranco Top 10K - 10,000 самых популярных и надежных сайтов интернета.
- **Черный список**: 240k+ известных фишинговых URL из JPCERT/CC (2020-2025).

## Что нового в v1.2
- ✅ **Tranco Top 10K** — надежный белый список из 10,000 самых посещаемых сайтов мира
- ✅ **Динамическая иконка** — аватар с цветным статусом (зеленый/красный/серый)
- ✅ **Статистика** — счетчик проверенных сайтов и заблокированных угроз
- ✅ **Улучшенная производительность** — оптимизированный поиск по спискам
- ✅ **Мгновенное обновление** — добавление в белый список работает сразу

## Датасеты
Проект использует объединенные датасеты для обучения модели:
1. **[ealvaradob/phishing-dataset](https://huggingface.co/datasets/ealvaradob/phishing-dataset)** (Hugging Face) - основной датасет.
2. **[Phishing and Legitimate URLs](https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls)** (Kaggle) - дополнительный датасет.

**Списки для расширения:**
- **[Tranco Top 10K](https://tranco-list.eu/)** - белый список 10,000 самых надежных доменов.
- **[JPCERT/CC PhishURL List](https://github.com/JPCERTCC/phishurl-list)** - черный список 240k+ фишинговых URL.

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
│   ├── assets/          # Белый и черный списки
│   └── manifest.json    # Конфиг расширения
├── models/              # Сохраненные модели
└── ...
```

## Установка и запуск

### 1. Обучение модели (Python)
```bash
pip install -r requirements.txt
python src/training/train.py
```

### 2. Установка расширения в Браузер

**Скачивание:**
```bash
git clone https://github.com/phantom2059/URL_detector.git
cd URL_detector
```

**Установка:**
1. Откройте `chrome://extensions/` (или `edge://extensions/`)
2. Включите **"Режим разработчика"**
3. Нажмите **"Загрузить распакованное расширение"**
4. Выберите папку `extension`

## Технические детали
- **Feature Extraction**: 70+ признаков, портированы с Python на JavaScript
- **ONNX Runtime Web**: WASM-бэкенд для запуска модели в браузере
- **Whitelist**: Tranco Top 10K + пользовательский список
- **Blacklist**: JPCERT/CC 2020-2025 (240k+ URL)

## Метрики модели
На отложенной выборке (20%):
- **Accuracy**: 96.21%
- **Precision**: 95.66%
- **Recall**: 97.23%
- **F1 Score**: 96.44%
- **ROC AUC**: 0.9935

## Changelog

### v1.2 (2025-01-XX)
- Добавлен Tranco Top 10K белый список
- Динамическая иконка с индикатором статуса
- Статистика проверок в настройках
- Оптимизация производительности
- Исправлена работа белого списка

### v1.1
- Добавлен черный список JPCERT/CC
- Темная/светлая тема
- Управление белым списком

### v1.0
- Первый релиз
- ML модель CatBoost + ONNX
- Базовый функционал расширения

## Лицензия
MIT License
