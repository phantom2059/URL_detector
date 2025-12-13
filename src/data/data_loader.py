import os
import sys

# Add the project root to the python path so we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import logging
import pandas as pd
import requests
from tqdm import tqdm
from huggingface_hub import hf_hub_download, list_repo_files
from src.config import config
from src.utils import utils

class DataLoader:
    def __init__(self):
        """Инициализация с конфигурацией."""
        self.dataset_name = config.DATASET_NAME
        self.cache_dir = os.path.abspath(config.DATA_CACHE_DIR)
        self.local_file_path = os.path.join(self.cache_dir, "dataset_merged.csv")
        self.ealvaradob_file_path = os.path.join(self.cache_dir, "dataset.csv")
        self.additional_file_path = os.path.join(self.cache_dir, "phishing_and_legitimate.csv")

    def dataset_exists_cached(self) -> bool:
        """Проверяет, скачан ли уже датасет локально."""
        return os.path.exists(self.local_file_path)

    def download_dataset(self, force_redownload=False):
        """
        Загружает датасет из Hugging Face и объединяет с локальным если есть.
        """
        if self.dataset_exists_cached() and not force_redownload:
            logging.info("Объединенный датасет уже существует локально. Пропуск скачивания.")
            return

        logging.info(f"Начало загрузки датасета {self.dataset_name}...")
        
        # Создаём директорию кэша если не существует
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        
        # 1. Загрузка ealvaradob/phishing-dataset (как раньше)
        if not os.path.exists(self.ealvaradob_file_path) or force_redownload:
            try:
                # ... (код загрузки с HF как был) ...
                logging.info("Получение списка файлов в репозитории...")
                files = list_repo_files(repo_id=self.dataset_name, repo_type="dataset")
                
                # Ищем CSV, Parquet или JSON файл
                data_file = None
                priority_files = ['combined_reduced.json', 'combined_full.json', 'urls.json']
                for pf in priority_files:
                    if pf in files:
                        data_file = pf
                        break
                if not data_file:
                    for f in files:
                        if f.endswith('.csv') and 'full' in f.lower(): data_file = f; break
                if not data_file:
                    for f in files:
                        if f.endswith('.csv'): data_file = f; break
                if not data_file:
                    for f in files:
                        if f.endswith('.parquet'): data_file = f; break
                if not data_file:
                    for f in files:
                        if f.endswith('.json') and not f.startswith('.'): data_file = f; break
                
                if not data_file:
                    raise FileNotFoundError(f"Не найден файл данных в репозитории {self.dataset_name}")
                
                logging.info(f"Загрузка файла: {data_file}")
                direct_url = f"https://huggingface.co/datasets/{self.dataset_name}/resolve/main/{data_file}"
                local_download_path = os.path.join(self.cache_dir, data_file)
                
                try:
                    logging.info(f"Загрузка через HTTP: {direct_url}")
                    response = requests.get(direct_url, stream=True, timeout=300)
                    response.raise_for_status()
                    total_size = int(response.headers.get('content-length', 0))
                    with open(local_download_path, 'wb') as f:
                        with tqdm(total=total_size, unit='B', unit_scale=True, desc="Загрузка HF") as pbar:
                            for chunk in response.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                                    pbar.update(len(chunk))
                    downloaded_path = local_download_path
                except Exception as http_err:
                    logging.warning(f"HTTP загрузка не удалась, пробуем huggingface_hub: {http_err}")
                    downloaded_path = hf_hub_download(repo_id=self.dataset_name, filename=data_file, repo_type="dataset", cache_dir=self.cache_dir)

                # Загружаем в pandas
                if data_file.endswith('.csv'): df = pd.read_csv(downloaded_path)
                elif data_file.endswith('.parquet'): df = pd.read_parquet(downloaded_path)
                elif data_file.endswith('.json'): df = pd.read_json(downloaded_path)
                else: raise ValueError(f"Unknown format {data_file}")
                
                # Нормализация
                # ealvaradob: 'url', 'label' usually? Or 'text', 'label'. Config has URL_COLUMN='text'
                # Let's standardize to 'url', 'label'
                
                # Find columns
                url_col = next((c for c in df.columns if c in ['url', 'URL', 'text', 'TEXT', 'link']), None)
                label_col = next((c for c in df.columns if c in ['label', 'Label', 'LABEL', 'is_phishing']), None)
                
                if url_col and label_col:
                    df = df.rename(columns={url_col: 'url', label_col: 'label'})
                    df = df[['url', 'label']]
                    # Convert labels to 0/1 if needed
                    # ealvaradob labels are often objects or ints. 1=phishing
                    # Ensure numeric
                    # Check unique values
                    # Usually 'benign', 'phishing' or 0, 1
                    pass
                
                df.to_csv(self.ealvaradob_file_path, index=False)
                
            except Exception as e:
                logging.error(f"Ошибка загрузки основного датасета: {e}")
                # Если не скачали, идем дальше, может второй есть
        
        # 2. Обработка дополнительного датасета (phishing_and_legitimate.csv)
        df_list = []
        
        if os.path.exists(self.ealvaradob_file_path):
            logging.info("Чтение основного датасета...")
            df1 = pd.read_csv(self.ealvaradob_file_path)
            # Стандартизация меток
            # ealvaradob has 'benign', 'phishing' sometimes? Need to check.
            # Assuming it is already clean or we clean it here.
            # Let's normalize labels: 1 for phishing, 0 for benign
            # If labels are strings 'phishing', 'benign'
            if df1['label'].dtype == object:
                 df1['label'] = df1['label'].apply(lambda x: 1 if str(x).lower() in ['phishing', '1', 'bad', 'malicious'] else 0)
            df_list.append(df1)
            
        if os.path.exists(self.additional_file_path):
            logging.info("Чтение дополнительного датасета (Kaggle)...")
            try:
                df2 = pd.read_csv(self.additional_file_path)
                # Kaggle dataset usually has 'URL' and 'Label' (0/1 or benign/phishing)
                # Check columns
                url_col = next((c for c in df2.columns if c.lower() == 'url'), None)
                label_col = next((c for c in df2.columns if c.lower() in ['label', 'status', 'class', 'target']), None)
                
                if url_col and label_col:
                    df2 = df2.rename(columns={url_col: 'url', label_col: 'label'})
                    df2 = df2[['url', 'label']]
                    # Normalize labels
                    # status: 'legitimate', 'phishing'
                    if df2['label'].dtype == object:
                        df2['label'] = df2['label'].apply(lambda x: 1 if str(x).lower() in ['phishing', '1', 'bad', 'malicious'] else 0)
                    
                    df_list.append(df2)
                    logging.info(f"Добавлено {len(df2)} записей из доп. датасета.")
                else:
                    logging.warning(f"Не найдены колонки URL/Label в {self.additional_file_path}. Колонки: {df2.columns}")
            except Exception as e:
                logging.error(f"Ошибка чтения доп. датасета: {e}")

        # 3. Объединение и перемешивание
        if df_list:
            full_df = pd.concat(df_list, ignore_index=True)
            logging.info(f"Всего записей до очистки: {len(full_df)}")
            
            # Удаление дубликатов
            # Handle potential KeyError if 'url' column is missing or named differently in one of the dataframes
            # Although we renamed them earlier, let's be safe and check columns of full_df
            if 'url' not in full_df.columns:
                 # Fallback: try to find the url column again or just use the first column? 
                 # Better to log error and raise
                 logging.error(f"Columns in merged dataframe: {full_df.columns}")
                 raise KeyError("Column 'url' not found in merged dataset")
                 
            full_df = full_df.drop_duplicates(subset=['url'])
            # Удаление пустых
            full_df = full_df.dropna(subset=['url', 'label'])
            
            # Перемешивание (Shuffle)
            full_df = full_df.sample(frac=1, random_state=42).reset_index(drop=True)
            
            logging.info(f"Всего записей после объединения и очистки: {len(full_df)}")
            full_df.to_csv(self.local_file_path, index=False)
            logging.info(f"Объединенный датасет сохранен в {self.local_file_path}")
        else:
            raise ValueError("Не удалось загрузить ни один датасет!")

    def load_and_prepare_data(self):
        """
        Возвращает (X_urls, y_labels, class_distribution)
        """
        if not self.dataset_exists_cached():
            self.download_dataset()

        logging.info(f"Чтение объединенного датасета из {self.local_file_path}...")
        df = pd.read_csv(self.local_file_path)
        
        url_col = 'url'
        label_col = 'label'
        
        # Check balance
        class_counts = df[label_col].value_counts(normalize=True)
        class_dist = class_counts.to_dict()
        
        X_urls = df[url_col].tolist()
        y_labels = df[label_col].tolist()
        
        return X_urls, y_labels, class_dist

    def get_class_distribution(self, labels):
        df = pd.DataFrame(labels, columns=['label'])
        return df['label'].value_counts(normalize=True).to_dict()
