import os
import sys

# Add the project root to the python path so we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import logging
from src.config import config
from typing import Optional

def setup_logging():
    """Настройка логирования в файл и консоль."""
    if not os.path.exists(config.LOG_DIR):
        os.makedirs(config.LOG_DIR)
        
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(config.LOG_DIR, "app.log")),
            logging.StreamHandler()
        ]
    )

def ensure_directories():
    """Создание всех необходимых директорий из конфига."""
    dirs = [
        config.DATA_CACHE_DIR, 
        config.MODELS_DIR, 
        config.PREPROCESSORS_DIR, 
        config.LOG_DIR
    ]
    for d in dirs:
        if not os.path.exists(d):
            os.makedirs(d)
            logging.info(f"Создана директория: {d}")

def load_config():
    """Перезагрузка или валидация конфигурации (заглушка)."""
    # В данном случае просто возвращаем модуль config, 
    # так как он уже импортирован. Можно добавить проверки.
    return config

def get_model_path(version: str) -> str:
    """Возвращает путь к файлу модели по версии."""
    return os.path.join(config.MODELS_DIR, f"model_{version}.pkl")

def get_scaler_path(version: str) -> str:
    """Возвращает путь к скейлеру по версии."""
    return os.path.join(config.PREPROCESSORS_DIR, f"scaler_{version}.pkl")

def get_feature_names_path(version: str) -> str:
    """Возвращает путь к файлу с именами признаков."""
    return os.path.join(config.MODELS_DIR, f"feature_names_{version}.pkl")

def get_metadata_path(version: str) -> str:
    """Возвращает путь к файлу метаданных."""
    return os.path.join(config.MODELS_DIR, f"model_info_{version}.json")
