import os

# Dataset configuration
DATASET_NAME = "ealvaradob/phishing-dataset"
DATA_CACHE_DIR = "./data_cache"  # Где кэшировать датасет
MODELS_DIR = "./models"    # Где сохранять модели
PREPROCESSORS_DIR = "./preprocessors"  # Где сохранять скейлеры

# Model Hyperparameters (CatBoost Best Found)
MODEL_CONFIG = {
    'iterations': 2481,
    'learning_rate': 0.04931391502294503,
    'depth': 10,
    'l2_leaf_reg': 5,
    'bootstrap_type': 'Bayesian',
    'random_strength': 2.8084481630053673,
    'grow_policy': 'SymmetricTree', # Forced for ONNX compatibility
    'bagging_temperature': 0.2918223839935979,
    'loss_function': 'Logloss',
    'verbose': 100,
    'random_seed': 127,
    'early_stopping_rounds': 100,
    'eval_metric': 'AUC',
    # 'task_type': 'CPU' # Removed to allow auto-detection in train.py
}

# Training configuration
TRAIN_TEST_SPLIT = 0.2 # Hold-out test set size
N_FOLDS = 5            # Number of CV folds
RANDOM_STATE = 127

# Logging configuration
LOG_DIR = "./logs"
LOG_LEVEL = "INFO"

# Dataset column names
URL_COLUMN = "text"  # As per ealvaradob/phishing-dataset
LABEL_COLUMN = "label"  # 0 = benign, 1 = phishing
