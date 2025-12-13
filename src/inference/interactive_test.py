import os
import sys

# Add the project root to the python path so we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import pandas as pd
from datetime import datetime
from src.utils import utils
from src.config import config
from src.inference.inference import URLPhishingDetector

def print_result(result):
    """Красивый вывод результата."""
    print("\n" + "="*50)
    print(f"URL: {result['url']}")
    print("-" * 50)
    
    status = "⚠️ ФИШИНГ" if result['is_phishing'] else "✅ БЕЗОПАСНО"
    color = "\033[91m" if result['is_phishing'] else "\033[92m"
    reset = "\033[0m"
    
    print(f"Статус: {color}{status}{reset}")
    print(f"Уровень риска: {result['risk_level']}")
    print(f"Вероятность: {result['probability_phishing']:.2%}")
    print("-" * 50)
    print(f"Объяснение: {result['explanation']}")
    print("="*50 + "\n")

def print_model_info(detector):
    """Вывод информации о модели."""
    if not detector.metadata:
        print("Метаданные модели отсутствуют.")
        return
        
    meta = detector.metadata
    print("\n=== Информация о модели ===")
    print(f"Версия: {meta.get('version')}")
    print(f"Дата обучения: {meta.get('timestamp')}")
    print(f"Датасет: {meta.get('dataset')}")
    print(f"Размер обучения: {meta.get('train_size')}")
    
    metrics = meta.get('metrics', {})
    print(f"Accuracy: {metrics.get('accuracy', 'N/A'):.4f}")
    print(f"F1 Score: {metrics.get('f1_score', 'N/A'):.4f}")
    print("===========================\n")

def main():
    utils.setup_logging()
    
    print("Инициализация детектора...")
    try:
        detector = URLPhishingDetector()
    except Exception as e:
        print(f"Ошибка инициализации: {e}")
        print("Сначала обучите модель (пункт 3 или 'python src/training/train.py')")
        # Allow menu to show even if model load fails, but some options won't work
        detector = None

    while True:
        print("\n=== Phishing URL Detector ===")
        print("1. Проверить один URL")
        print("2. Проверить URLs из файла")
        print("3. Загрузить датасет и обучить новую модель")
        print("4. Показать информацию о текущей модели")
        print("5. Выход")
        
        choice = input("Выбор (1-5): ").strip()
        
        if choice == '1':
            if not detector:
                print("Модель не загружена. Обучите модель сначала.")
                continue
                
            url = input("Введите URL: ").strip()
            if url:
                try:
                    result = detector.predict_single(url)
                    print_result(result)
                except Exception as e:
                    print(f"Ошибка при проверке: {e}")
            
        elif choice == '2':
            if not detector:
                print("Модель не загружена.")
                continue
                
            filepath = input("Путь к файлу (один URL на строку): ").strip()
            if not os.path.exists(filepath):
                print("Файл не найден.")
                continue
                
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]
                
                print(f"Загружено {len(urls)} URLs. Обработка...")
                results = detector.predict_batch(urls)
                
                # Save results
                df = pd.DataFrame(results)
                output_file = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                df.to_csv(output_file, index=False)
                print(f"Результаты сохранены в {output_file}")
                
                # Show summary
                phishing_count = df['is_phishing'].sum()
                print(f"Найдено фишинга: {phishing_count} / {len(urls)}")
                
            except Exception as e:
                print(f"Ошибка обработки файла: {e}")
            
        elif choice == '3':
            print("Запуск обучения...")
            try:
                # Import here to avoid loading heavy libs if not needed immediately
                from src.training import train
                train.main()
                # Reload detector
                detector = URLPhishingDetector()
            except Exception as e:
                print(f"Ошибка обучения: {e}")
            
        elif choice == '4':
            if detector:
                print_model_info(detector)
            else:
                print("Модель не загружена.")
            
        elif choice == '5':
            print("Выход...")
            break
        else:
            print("Неверный выбор.")

if __name__ == '__main__':
    main()
