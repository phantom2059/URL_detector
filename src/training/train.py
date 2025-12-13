import os
import sys
import argparse

# Add the project root to the python path so we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import logging
import json
import time
from datetime import datetime
import joblib
import numpy as np
import pandas as pd
from tqdm import tqdm
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns
from catboost import CatBoostClassifier, Pool
from skl2onnx import to_onnx
from skl2onnx.common.data_types import FloatTensorType
import onnx

from src.config import config
from src.utils import utils
from src.data.data_loader import DataLoader
from src.data.feature_extractor import FeatureExtractor

def plot_confusion_matrix(y_true, y_pred, save_path):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False)
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.savefig(save_path)
    plt.close()

def plot_feature_importance(model, feature_names, save_path):
    importances = model.get_feature_importance()
    indices = np.argsort(importances)[::-1][:20]  # Top 20
    
    plt.figure(figsize=(12, 8))
    plt.title("Top 20 Feature Importances")
    plt.bar(range(len(indices)), importances[indices], align="center")
    plt.xticks(range(len(indices)), [feature_names[i] for i in indices], rotation=90)
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()

def print_top_features(model, feature_names, top_n=20):
    """Вывод топовых признаков в консоль."""
    importances = model.get_feature_importance()
    indices = np.argsort(importances)[::-1][:top_n]
    
    print(f"\n=== Top {top_n} Feature Importances ===")
    for i in indices:
        print(f"{feature_names[i]:<40} : {importances[i]:.4f}")
    print("=======================================\n")

def main():
    parser = argparse.ArgumentParser(description="Phishing URL Detector Training")
    parser.add_argument('--gpu', action='store_true', help='Force Use GPU for training (otherwise auto-detect)')
    parser.add_argument('--trials', type=int, default=0, help='Number of trials for hyperparameter tuning (0 to skip)')
    args = parser.parse_args()
    
    # 1. Настройка
    utils.setup_logging()
    utils.ensure_directories()
    
    # Автоматическое определение GPU для CatBoost
    task_type = 'CPU'
    try:
        from catboost.utils import get_gpu_device_count
        gpu_count = get_gpu_device_count()
        if gpu_count > 0:
            logging.info(f"Обнаружено {gpu_count} GPU. Используем GPU для обучения.")
            task_type = 'GPU'
        else:
            logging.info("GPU не обнаружено. Используем CPU.")
            
        # Если пользователь принудительно указал флаг --gpu, но его нет - предупредим
        if args.gpu and gpu_count == 0:
            logging.warning("Флаг --gpu указан, но устройства не найдены. Оставляем CPU.")
            
    except Exception as e:
        logging.warning(f"Не удалось проверить GPU: {e}. Использую CPU по умолчанию.")
        task_type = 'CPU'

    logging.info(f"=== Запуск обучения модели детекции фишинга (CatBoost, {task_type}, K-Fold) ===")
    
    # 2. Загрузка данных
    loader = DataLoader()
    X_urls, y_labels, class_dist = loader.load_and_prepare_data()
    logging.info(f"Баланс классов: {class_dist}")
    
    # 3. Извлечение признаков (с кэшированием)
    extractor = FeatureExtractor()
    features_cache_path = os.path.join(config.DATA_CACHE_DIR, "features_cache.pkl")
    
    features_list = []
    use_cache = False
    
    if os.path.exists(features_cache_path):
        logging.info("Найден кэш признаков, попытка загрузки...")
        try:
            cached_features = joblib.load(features_cache_path)
            if len(cached_features) == len(X_urls):
                logging.info(f"Успешно загружено {len(cached_features)} признаков из кэша.")
                features_list = cached_features
                use_cache = True
            else:
                logging.warning("Размер кэша не совпадает с размером датасета. Пересчет признаков.")
        except Exception as e:
            logging.warning(f"Ошибка загрузки кэша: {e}. Пересчет признаков.")
    
    if not use_cache:
        logging.info("Начало извлечения признаков...")
        for url in tqdm(X_urls, desc="Извлечение признаков"):
            features_list.append(extractor.extract_features(url))
        
        # Save cache
        logging.info("Сохранение кэша признаков...")
        joblib.dump(features_list, features_cache_path)
        
    df_features = pd.DataFrame(features_list)
    feature_names = extractor.get_feature_names()
    logging.info(f"Извлечено {len(feature_names)} признаков.")
    
    # 4. Предварительная обработка
    logging.info("Подготовка данных для обучения...")
    X = df_features[feature_names].values
    y = np.array(y_labels)
    
    # Используем сырые данные (CatBoost сам умеет квантовать)
    X = X.astype(np.float32)
    
    # Разделение на train/test (Hold-out для финальной валидации)
    X_train_full, X_holdout, y_train_full, y_holdout = train_test_split(
        X, y, 
        test_size=config.TRAIN_TEST_SPLIT, 
        random_state=config.RANDOM_STATE,
        stratify=y
    )
    
    logging.info(f"Размер обучающей выборки (Full): {X_train_full.shape}")
    logging.info(f"Размер отложенной выборки (Hold-out): {X_holdout.shape}")
    
    # Заглушка скалера для совместимости
    scaler = StandardScaler()
    scaler.mean_ = np.zeros(X_train_full.shape[1])
    scaler.scale_ = np.ones(X_train_full.shape[1])
    scaler.var_ = np.ones(X_train_full.shape[1])
    
    # 5. K-Fold Training
    logging.info(f"Запуск K-Fold кросс-валидации ({config.N_FOLDS} фолдов)...")
    skf = StratifiedKFold(n_splits=config.N_FOLDS, shuffle=True, random_state=config.RANDOM_STATE)
    
    best_model = None
    best_auc = 0.0
    best_fold = -1
    
    model_params = config.MODEL_CONFIG.copy()
    model_params['task_type'] = task_type
    
    for fold, (train_idx, val_idx) in enumerate(skf.split(X_train_full, y_train_full)):
        logging.info(f"\n--- Fold {fold+1}/{config.N_FOLDS} ---")
        
        X_train_fold, X_val_fold = X_train_full[train_idx], X_train_full[val_idx]
        y_train_fold, y_val_fold = y_train_full[train_idx], y_train_full[val_idx]
        
        train_pool = Pool(X_train_fold, y_train_fold)
        val_pool = Pool(X_val_fold, y_val_fold)
        
        try:
            model = CatBoostClassifier(**model_params)
            model.fit(train_pool, eval_set=val_pool)
            
            # Оценка на валидации фолда
            y_pred_val = model.predict_proba(X_val_fold)[:, 1]
            fold_auc = roc_auc_score(y_val_fold, y_pred_val)
            logging.info(f"Fold {fold+1} ROC AUC: {fold_auc:.4f}")
            
            if fold_auc > best_auc:
                best_auc = fold_auc
                best_model = model
                best_fold = fold + 1
                
        except Exception as e:
            if task_type == 'GPU' and "GPU" in str(e):
                logging.error(f"Ошибка обучения на GPU: {e}. Переключаюсь на CPU для этого фолда...")
                model_params['task_type'] = 'CPU'
                model = CatBoostClassifier(**model_params)
                model.fit(train_pool, eval_set=val_pool)
                # ... same evaluation logic ...
            else:
                raise e

    logging.info(f"\nЛучший фолд: {best_fold} с ROC AUC: {best_auc:.4f}")
    
    # 6. Финальная оценка лучшей модели на Hold-out
    logging.info("Оценка лучшей модели на отложенной выборке...")
    y_pred = best_model.predict(X_holdout)
    y_prob = best_model.predict_proba(X_holdout)[:, 1]
    
    accuracy = accuracy_score(y_holdout, y_pred)
    precision = precision_score(y_holdout, y_pred)
    recall = recall_score(y_holdout, y_pred)
    f1 = f1_score(y_holdout, y_pred)
    roc_auc = roc_auc_score(y_holdout, y_prob)
    
    logging.info(f"Hold-out Accuracy: {accuracy:.4f}")
    logging.info(f"Hold-out Precision: {precision:.4f}")
    logging.info(f"Hold-out Recall: {recall:.4f}")
    logging.info(f"Hold-out F1 Score: {f1:.4f}")
    logging.info(f"Hold-out ROC AUC: {roc_auc:.4f}")
    
    print("\nClassification Report (Hold-out):")
    print(classification_report(y_holdout, y_pred))
    
    # Визуализация
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    version = f"v{timestamp}_best_fold{best_fold}"
    
    plot_confusion_matrix(y_holdout, y_pred, os.path.join(config.LOG_DIR, f"confusion_matrix_{version}.png"))
    plot_feature_importance(best_model, feature_names, os.path.join(config.LOG_DIR, f"feature_importance_{version}.png"))
    print_top_features(best_model, feature_names)
    
    # 7. Сохранение
    logging.info(f"Сохранение лучшей модели версии {version}...")
    
    # Пути
    model_path = utils.get_model_path(version).replace(".pkl", ".cbm")
    onnx_path = utils.get_model_path(version).replace(".pkl", ".onnx")
    scaler_path = utils.get_scaler_path(version)
    feature_names_path = utils.get_feature_names_path(version)
    metadata_path = utils.get_metadata_path(version)
    
    # Сохраняем CatBoost модель
    best_model.save_model(model_path)
    
    # Конвертация в ONNX
    logging.info("Конвертация модели в ONNX...")
    try:
        best_model.save_model(onnx_path, format="onnx")
        logging.info(f"ONNX модель сохранена в {onnx_path}")
    except Exception as e:
        logging.error(f"Ошибка экспорта в ONNX: {e}")

    # Сохраняем остальные объекты
    joblib.dump(scaler, scaler_path)
    joblib.dump(feature_names, feature_names_path)
    
    # Also save as 'latest'
    best_model.save_model(utils.get_model_path("latest").replace(".pkl", ".cbm"))
    if os.path.exists(onnx_path):
        import shutil
        shutil.copy(onnx_path, utils.get_model_path("latest").replace(".pkl", ".onnx"))
        
    joblib.dump(scaler, utils.get_scaler_path("latest"))
    joblib.dump(feature_names, utils.get_feature_names_path("latest"))
    
    # Метаданные
    metadata = {
        "version": version,
        "timestamp": timestamp,
        "dataset": config.DATASET_NAME,
        "train_size": len(X_train_full), # Total training set size
        "test_size": len(X_holdout),
        "best_fold": best_fold,
        "metrics": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "roc_auc": float(roc_auc)
        },
        "model_params": model_params,
        "feature_names": feature_names,
        "model_type": "catboost"
    }
    
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=4, ensure_ascii=False)
        
    with open(utils.get_metadata_path("latest"), 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=4, ensure_ascii=False)
        
    logging.info("Все данные успешно сохранены.")
    logging.info("=== Обучение завершено успешно ===")

if __name__ == "__main__":
    main()
