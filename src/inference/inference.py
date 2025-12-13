import os
import sys

# Add the project root to the python path so we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import joblib
import json
import pandas as pd
import numpy as np
import logging
from catboost import CatBoostClassifier

from src.utils import utils
from src.config import config
from src.data.feature_extractor import FeatureExtractor

class URLPhishingDetector:
    def __init__(self, model_version="latest"):
        """
        Загружает модель, скейлер и метаданные.
        """
        self.model_version = model_version
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.metadata = None
        self.extractor = FeatureExtractor()
        
        self._load_model_artifacts()

    def _load_model_artifacts(self):
        """Внутренний метод для загрузки файлов."""
        try:
            # Check for CatBoost model file first (.cbm)
            model_path_cbm = utils.get_model_path(self.model_version).replace(".pkl", ".cbm")
            # Fallback to .pkl if needed (for older models)
            model_path_pkl = utils.get_model_path(self.model_version)
            
            scaler_path = utils.get_scaler_path(self.model_version)
            features_path = utils.get_feature_names_path(self.model_version)
            metadata_path = utils.get_metadata_path(self.model_version)
            
            if os.path.exists(model_path_cbm):
                self.model = CatBoostClassifier()
                self.model.load_model(model_path_cbm)
                logging.info(f"Загружена CatBoost модель: {model_path_cbm}")
            elif os.path.exists(model_path_pkl):
                self.model = joblib.load(model_path_pkl)
                logging.info(f"Загружена Pickle модель: {model_path_pkl}")
            else:
                raise FileNotFoundError(f"Модель не найдена (искал {model_path_cbm} и {model_path_pkl}). Сначала запустите train.py.")
                
            self.scaler = joblib.load(scaler_path)
            self.feature_names = joblib.load(features_path)
            
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r', encoding='utf-8') as f:
                    self.metadata = json.load(f)
                    
            logging.info(f"Загружена версия {self.model_version}")
            
        except Exception as e:
            logging.error(f"Ошибка загрузки модели: {e}")
            raise

    def predict_single(self, url: str) -> dict:
        """
        Предсказание для одного URL.
        Возвращает детальный словарь с вероятностями и объяснением.
        """
        # Извлечение признаков
        features = self.extractor.extract_features(url)
        
        # Подготовка вектора
        # Важно сохранить порядок признаков как при обучении
        feature_vector = [features[name] for name in self.feature_names]
        X = np.array([feature_vector])
        
        # Масштабирование (нужно для совместимости, даже если CatBoost мог бы без него)
        # В train.py мы перешли на float32, но scaler остался (хоть и заглушка).
        # Важно применить трансформацию если scaler был обучен (или это заглушка).
        X_scaled = self.scaler.transform(X).astype(np.float32)
        
        # Предсказание
        prediction = self.model.predict(X_scaled)[0]
        probs = self.model.predict_proba(X_scaled)[0]
        
        prob_legit = probs[0]
        prob_phish = probs[1]
        
        confidence = prob_phish if prediction == 1 else prob_legit
        
        # Определение уровня риска
        if prob_phish > 0.9:
            risk_level = "CRITICAL"
        elif prob_phish > 0.75:
            risk_level = "HIGH"
        elif prob_phish > 0.5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        explanation = self.explain_prediction(url, features, prediction, prob_phish)
        
        return {
            'url': url,
            'prediction': int(prediction), # 0 or 1
            'is_phishing': bool(prediction == 1),
            'probability_phishing': float(prob_phish),
            'probability_legitimate': float(prob_legit),
            'confidence': float(confidence),
            'risk_level': risk_level,
            'explanation': explanation,
            'features': features # Optional: return extracted features for debug
        }

    def predict_batch(self, urls: list) -> list:
        """Предсказание для списка URLs."""
        return [self.predict_single(url) for url in urls]

    def explain_prediction(self, url: str, features: dict, prediction: int, prob_phish: float) -> str:
        """Генерация текстового объяснения."""
        reasons = []
        
        if prediction == 1:
            if features.get('has_ip_address'):
                reasons.append("использует IP-адрес вместо домена")
            if features.get('has_suspicious_keywords'):
                reasons.append("содержит подозрительные ключевые слова")
            if features.get('url_length') > 75:
                reasons.append("имеет аномально большую длину")
            if features.get('qty_dot_url') > 3:
                reasons.append("содержит много точек")
            if features.get('has_at_symbol'): 
                 reasons.append("содержит символ @")
            if features.get('qty_slash_url') > 5:
                reasons.append("глубокая структура пути")
            if features.get('tld_length') > 4 and features.get('tld_length') < 10:
                 reasons.append("необычная длина TLD")
            if features.get('has_sensitive_words'):
                 reasons.append("содержит чувствительные слова (пароль, оплата)")
                 
            # Add more specific logic based on feature values
            if not reasons:
                reasons.append("обнаружены скрытые паттерны фишинга")
                
            return f"URL классифицирован как ФИШИНГ ({prob_phish:.1%}). Причины: {', '.join(reasons)}."
        else:
            return f"URL классифицирован как безопасный ({1-prob_phish:.1%})."
