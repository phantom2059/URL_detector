# Phishing URL Detector - ML Model

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![CatBoost](https://img.shields.io/badge/CatBoost-1.2%2B-orange)

## Описание
Мощная модель машинного обучения для автоматического определения фишинговых URL-адресов. Проект включает полный цикл от загрузки и объединения данных до инференса и поддерживает экспорт в ONNX для использования в веб-среде (браузерные расширения, frontend).

## Основные возможности
- **Движок**: CatBoost (Градиентный бустинг) с автоматическим использованием GPU.
- **Точность**: ~96.2% (Accuracy), ROC AUC ~0.993
- **Данные**: Объединенный датасет (~800k+ URL) из `ealvaradob/phishing-dataset` и Kaggle `phishing-site-urls`.
- **Признаки**: 70+ признаков (структурные, лексические, доменные, энтропия).
- **Экспорт**: ONNX формат для кросс-платформенного запуска (поддержка NPU/GPU в браузере).
- **Валидация**: Stratified K-Fold (5 фолдов) + Hold-out test set для максимальной надежности.

## Установка

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/phantom2059/URL_detector.git
   cd URL_detector
   ```

2. Создайте виртуальное окружение:
   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate  # Windows
   source .venv/bin/activate # Linux/Mac
   ```

3. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

## Использование

### 1. Обучение модели
Скрипт автоматически скачает данные (с Hugging Face и зеркал), объединит их, удалит дубликаты, извлечет признаки (с кэшированием) и обучит модель. Автоматически определит наличие GPU для ускорения.

```bash
python src/training/train.py
```

Опции (опционально):
- `--gpu`: Принудительно использовать GPU (скрипт и так пытается найти его).
- `--trials N`: Запустить N итераций подбора гиперпараметров через Optuna.

### 2. Интерактивное тестирование
Запустите консольное меню для проверки URL вручную:

```bash
python src/inference/interactive_test.py
```

### 3. Прямой инференс из кода

```python
from src.inference.inference import URLPhishingDetector

# Инициализация (загрузит лучшую модель)
detector = URLPhishingDetector()

# Проверка URL
url = "https://suspicious-paypal-login.com"
result = detector.predict_single(url)

print(f"Риск: {result['risk_level']}")
print(f"Вероятность: {result['probability_phishing']:.2%}")
print(f"Причина: {result['explanation']}")
```

## Структура проекта
```
phishing-detector/
├── src/
│   ├── config/          # Конфигурация
│   ├── data/            # Загрузка данных и экстрактор признаков
│   ├── training/        # Скрипты обучения (K-Fold, Optuna)
│   ├── inference/       # Скрипты инференса
│   └── utils/           # Утилиты
├── data_cache/          # Кэш датасетов (авто-создается)
├── models/              # Обученные модели (.cbm, .onnx)
├── preprocessors/       # Скейлеры
├── logs/                # Логи и графики метрик
├── .gitignore           # Игнорируемые файлы (модели, кэш, логи)
└── requirements.txt     # Зависимости
```

## Метрики модели (Best Fold)
На отложенной выборке (20% от 800k):
- **Accuracy**: 96.21%
- **Precision**: 95.66%
- **Recall**: 97.23%
- **F1 Score**: 96.44%
- **ROC AUC**: 0.9935

## Признаки
Модель анализирует более 70 признаков, включая:
- Глубину URL (`url_depth`), длину пути (`path_length`)
- Количество спецсимволов (`qty_slash`, `qty_colon`, `qty_dot`...)
- Наличие HTTPS, IP-адресов, сокращателей ссылок
- Энтропию домена и URL (случайность символов)
- Наличие подозрительных слов (secure, login...) и брендов
- Соотношение цифр/букв, длину TLD и домена

## Экспорт в ONNX
После обучения модель автоматически конвертируется в формат `.onnx` и сохраняется в папку `models/`. Это позволяет запускать её в браузере с помощью `onnxruntime-web` без использования Python-бэкенда, используя аппаратное ускорение клиента (WebGL/WebGPU/NPU).
