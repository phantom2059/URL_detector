import re
import math
from urllib.parse import urlparse, parse_qs
import numpy as np

class FeatureExtractor:
    
    SUSPICIOUS_KEYWORDS = {
        'login', 'verify', 'secure', 'confirm', 'account', 'update', 
        'alert', 'urgent', 'action', 'payment', 'transaction', 'click',
        'reset', 'recover', 'validate', 'authenticate', 'access', 
        'activate', 'confirm', 'password', 'change', 'immediately'
    }
    
    BRAND_KEYWORDS = {
        'amazon', 'paypal', 'google', 'facebook', 'apple', 'microsoft',
        'netflix', 'bank', 'visa', 'mastercard', 'ebay', 'uber',
        'dropbox', 'onedrive', 'instagram', 'twitter', 'linkedin'
    }
    
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq',  # Бесплатные TLD часто используются в фишинге
        'icu', 'pw', 'top', 'men', 'download',  # Дешёвые и подозрительные
        'online', 'site', 'space', 'website', 'host'
    }
    
    COMMON_TLDS = {
        'com', 'org', 'net', 'ru', 'us', 'uk', 'de', 'fr', 'it', 'es',
        'gov', 'edu', 'info', 'biz', 'co'
    }
    
    SUSPICIOUS_SUBDOMAINS = {
        'admin', 'login', 'secure', 'bank', 'paypal', 'verify', 'confirm',
        'update', 'activate', 'signin', 'accounts', 'user', 'panel'
    }
    
    # ============ СТРУКТУРНЫЕ ПРИЗНАКИ ============
    
    def _url_length(self, parsed) -> int:
        """Общая длина URL"""
        return len(parsed.geturl())
    
    def _domain_length(self, parsed) -> int:
        """Длина домена"""
        return len(parsed.netloc)
    
    def _subdomain_count(self, parsed) -> int:
        """Количество точек в домене - 1"""
        return parsed.netloc.count('.') - 1 if '.' in parsed.netloc else 0
    
    def _path_length(self, parsed) -> int:
        """Длина пути"""
        return len(parsed.path)
    
    def _query_length(self, parsed) -> int:
        """Длина query string"""
        return len(parsed.query)
    
    def _fragment_length(self, parsed) -> int:
        """Длина fragment"""
        return len(parsed.fragment)
    
    def _has_ip_address(self, parsed) -> int:
        """1 если IP, 0 если домен"""
        import re
        host = parsed.netloc.split(':')[0]
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return 1 if re.match(ip_pattern, host) else 0
    
    def _has_port(self, parsed) -> int:
        """1 если есть порт"""
        return 1 if ':' in parsed.netloc else 0
    
    def _port_number(self, parsed) -> int:
        """Номер порта или -1"""
        if ':' in parsed.netloc:
            try:
                return int(parsed.netloc.split(':')[1])
            except:
                return -1
        return -1
    
    def _has_https(self, parsed) -> int:
        """1 если HTTPS"""
        return 1 if parsed.scheme == 'https' else 0
    
    def _has_https_in_domain(self, url) -> int:
        """1 если 'https' в части домена (подделка)"""
        parts = url.lower().split('://')
        if len(parts) > 1:
            domain_part = parts[1].split('/')[0]
            return 1 if 'https' in domain_part else 0
        return 0
    
    def _has_http_in_domain(self, url) -> int:
        """1 если 'http' в части домена"""
        parts = url.lower().split('://')
        if len(parts) > 1:
            domain_part = parts[1].split('/')[0]
            return 1 if 'http' in domain_part else 0
        return 0
    
    def _has_url_shortener(self, parsed) -> int:
        """1 если сокращатель (bit.ly, tinyurl и т.д.)"""
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'short.link', 
                      'lnk.co', 't.co', 'shortened.link', 'is.gd', 'cli.gs']
        return 1 if any(short in parsed.netloc.lower() for short in shorteners) else 0
    
    def _has_at_symbol(self, url) -> int:
        """1 если @ (может скрывать настоящий домен)"""
        return 1 if '@' in url else 0
    
    def _has_double_slash_redirect(self, parsed) -> int:
        """1 если // в пути (редирект признак)"""
        return 1 if '//' in parsed.path else 0
    
    def _url_depth(self, parsed) -> int:
        """Глубина пути (количество слешей)"""
        return parsed.path.count('/')
    
    # ============ СИМВОЛЬНЫЕ ПРИЗНАКИ ============
    
    def _qty_dot_url(self, url) -> int:
        """Количество точек"""
        return url.count('.')
    
    def _qty_hyphen_url(self, url) -> int:
        """Количество дефисов"""
        return url.count('-')
    
    def _qty_slash_url(self, url) -> int:
        """Количество слешей"""
        return url.count('/')
    
    def _qty_question_url(self, url) -> int:
        """Количество ?"""
        return url.count('?')
    
    def _qty_percent_url(self, url) -> int:
        """Количество %"""
        return url.count('%')
    
    def _qty_at_url(self, url) -> int:
        """Количество @"""
        return url.count('@')
    
    def _qty_ampersand_url(self, url) -> int:
        """Количество &"""
        return url.count('&')
    
    def _qty_equal_url(self, url) -> int:
        """Количество ="""
        return url.count('=')
    
    def _qty_underscore_url(self, url) -> int:
        """Количество _"""
        return url.count('_')
    
    def _qty_colon_url(self, url) -> int:
        """Количество :"""
        return url.count(':')
    
    def _qty_semicolon_url(self, url) -> int:
        """Количество ;"""
        return url.count(';')
    
    def _qty_comma_url(self, url) -> int:
        """Количество ,"""
        return url.count(',')
    
    def _qty_vowels_url(self, url) -> int:
        """Количество гласных"""
        vowels = 'aeiouAEIOU'
        return sum(1 for c in url if c in vowels)
    
    def _qty_digits_url(self, url) -> int:
        """Количество цифр"""
        return sum(1 for c in url if c.isdigit())
    
    def _qty_uppercase_url(self, url) -> int:
        """Количество заглавных букв"""
        return sum(1 for c in url if c.isupper())
    
    def _entropy_url(self, url) -> float:
        """Энтропия Шеннона всего URL"""
        import math
        from collections import Counter
        if len(url) == 0:
            return 0.0
        counter = Counter(url)
        entropy = 0.0
        for count in counter.values():
            p = count / len(url)
            entropy -= p * math.log2(p)
        return entropy
    
    def _entropy_domain(self, parsed) -> float:
        """Энтропия только домена"""
        import math
        from collections import Counter
        domain = parsed.netloc
        if len(domain) == 0:
            return 0.0
        counter = Counter(domain)
        entropy = 0.0
        for count in counter.values():
            p = count / len(domain)
            entropy -= p * math.log2(p)
        return entropy
    
    def _qty_consecutive_dots(self, url) -> int:
        """Количество подряд идущих точек"""
        return url.count('..')
    
    # ============ ДОМЕННЫЕ ПРИЗНАКИ ============
    
    def _tld_length(self, parsed) -> int:
        """Длина расширения"""
        domain = parsed.netloc.split(':')[0]
        parts = domain.split('.')
        return len(parts[-1]) if len(parts) > 1 else 0
    
    def _domain_extension(self, parsed) -> int:
        """Кодирование типа расширения"""
        domain = parsed.netloc.split(':')[0]
        parts = domain.split('.')
        if len(parts) > 1:
            tld = parts[-1].lower()
            tld_map = {
                'com': 1, 'ru': 2, 'net': 3, 'org': 4, 'uk': 5,
                'de': 6, 'jp': 7, 'fr': 8, 'au': 9, 'us': 10,
                'ca': 11, 'info': 12, 'biz': 13, 'xyz': 14, 'top': 15,
                'cn': 16, 'in': 17, 'br': 18, 'io': 19, 'online': 20
            }
            return tld_map.get(tld, 0)
        return 0
    
    def _has_common_tld(self, parsed) -> int:
        """1 если частое расширение"""
        domain = parsed.netloc.split(':')[0]
        parts = domain.split('.')
        if len(parts) > 1:
            tld = parts[-1].lower()
            return 1 if tld in self.COMMON_TLDS else 0
        return 0
    
    def _has_suspicious_tld(self, parsed) -> int:
        """1 если подозрительное расширение"""
        domain = parsed.netloc.split(':')[0]
        parts = domain.split('.')
        if len(parts) > 1:
            tld = parts[-1].lower()
            return 1 if tld in self.SUSPICIOUS_TLDS else 0
        return 0
    
    def _qty_hyphens_domain(self, parsed) -> int:
        """Дефисы в домене"""
        domain = parsed.netloc.split(':')[0]
        return domain.count('-')
    
    def _qty_underscores_domain(self, parsed) -> int:
        """Подчёркивания в домене"""
        domain = parsed.netloc.split(':')[0]
        return domain.count('_')
    
    def _has_multiple_domains(self, url) -> int:
        """Несколько доменов"""
        return 1 if url.lower().count('http') > 1 else 0
    
    def _domain_digits_ratio(self, parsed) -> float:
        """Отношение цифр к буквам в домене"""
        domain = parsed.netloc.split(':')[0]
        digits = sum(1 for c in domain if c.isdigit())
        letters = sum(1 for c in domain if c.isalpha())
        return digits / letters if letters > 0 else 0.0
    
    # ============ ЛЕКСИЧЕСКИЕ ПРИЗНАКИ ============
    
    def _has_suspicious_keywords(self, url) -> int:
        """1 если есть подозрительные слова"""
        url_lower = url.lower()
        return 1 if any(keyword in url_lower for keyword in self.SUSPICIOUS_KEYWORDS) else 0
    
    def _qty_suspicious_keywords(self, url) -> int:
        """Количество подозрительных слов"""
        url_lower = url.lower()
        return sum(1 for keyword in self.SUSPICIOUS_KEYWORDS if keyword in url_lower)
    
    def _has_brand_mimicking(self, url) -> int:
        """1 если подражание брендам"""
        url_lower = url.lower()
        return 1 if any(brand in url_lower for brand in self.BRAND_KEYWORDS) else 0
    
    def _qty_brand_mimicking(self, url) -> int:
        """Количество попыток подражания"""
        url_lower = url.lower()
        return sum(1 for brand in self.BRAND_KEYWORDS if brand in url_lower)
    
    def _has_numeric_only_domain(self, parsed) -> int:
        """Домен только из цифр"""
        domain = parsed.netloc.split(':')[0]
        return 1 if domain.replace('.', '').isdigit() else 0
    
    def _has_consecutive_letters(self, url) -> int:
        """1 если много повторяющихся букв"""
        import re
        return 1 if re.search(r'(.)\1{2,}', url) else 0
    
    def _has_numerics_in_domain(self, parsed) -> int:
        """Цифры в домене"""
        domain = parsed.netloc.split(':')[0]
        return 1 if any(c.isdigit() for c in domain) else 0
    
    def _has_repeated_subdomains(self, parsed) -> int:
        """Повторение подпапок"""
        domain = parsed.netloc.split(':')[0]
        parts = domain.split('.')
        subdomains = parts[:-1]
        if not subdomains:
            return 0
        return 1 if len(subdomains) != len(set(subdomains)) else 0
    
    def _qty_slashes_path(self, parsed) -> int:
        """Количество слешей в пути"""
        return parsed.path.count('/')
    
    def _qty_dots_path(self, parsed) -> int:
        """Количество точек в пути"""
        return parsed.path.count('.')
    
    def _path_has_parameters(self, parsed) -> int:
        """1 если есть параметры"""
        return 1 if parsed.query else 0
    
    def _qty_parameters(self, parsed) -> int:
        """Количество параметров"""
        return parsed.query.count('&') + (1 if parsed.query else 0)
    
    def _has_base64_encoding(self, url) -> int:
        """1 если base64"""
        import re
        return 1 if re.search(r'[A-Za-z0-9+/]{25,}={0,2}', url) else 0
    
    def _has_hex_encoding(self, url) -> int:
        """1 если HEX кодирование"""
        return 1 if '%' in url else 0
    
    def _has_obfuscation(self, url) -> int:
        """1 если кодирование вообще"""
        return 1 if ('%' in url or self._has_base64_encoding(url)) else 0
    
    # ============ РЕДИРЕКТЫ И ПЕРЕНАПРАВЛЕНИЯ ============
    
    def _has_localhost(self, parsed) -> int:
        """1 если localhost"""
        return 1 if 'localhost' in parsed.netloc.lower() else 0
    
    def _has_internal_ip(self, parsed) -> int:
        """1 если внутренний IP"""
        import re
        ip = parsed.netloc.split(':')[0]
        internal_ips = [
            r'^192\.168\.',
            r'^10\.',
            r'^172\.1[6-9]\.',
            r'^172\.2[0-9]\.',
            r'^172\.3[0-1]\.'
        ]
        return 1 if any(re.match(pattern, ip) for pattern in internal_ips) else 0
    
    def _has_suspicious_protocol(self, parsed) -> int:
        """1 если необычный протокол"""
        if not parsed.scheme:
            return 0
        return 1 if parsed.scheme not in ['http', 'https'] else 0
    
    def _has_javascript_protocol(self, url) -> int:
        """1 если javascript: протокол"""
        return 1 if 'javascript:' in url.lower() else 0
    
    def _has_data_protocol(self, url) -> int:
        """1 если data: протокол"""
        return 1 if 'data:' in url.lower() else 0
    
    # ============ СПЕЦИАЛЬНЫЕ СИМВОЛЫ ============
    
    def _has_email_format(self, url) -> int:
        """1 если email-подобная структура"""
        import re
        return 1 if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url) else 0
    
    def _qty_special_chars(self, url) -> int:
        """Количество спецсимволов"""
        special = set('!@#$%^&*()_+-=[]{}|;:",.<>?/~`')
        return sum(1 for c in url if c in special)
    
    def _ratio_special_to_length(self, url) -> float:
        """Отношение спецсимволов к длине"""
        if not url:
            return 0.0
        return self._qty_special_chars(url) / len(url)
    
    def _has_uncommon_chars(self, url) -> int:
        """1 если необычные символы"""
        try:
            url.encode('ascii')
            return 0
        except UnicodeEncodeError:
            return 1
    
    def _has_punycode(self, url) -> int:
        """1 если punycode (xn--)"""
        return 1 if 'xn--' in url.lower() else 0
    
    def _has_unicode_chars(self, url) -> int:
        """1 если unicode"""
        return 1 if any(ord(c) > 127 for c in url) else 0
    
    def _has_mixed_scripts(self, url) -> int:
        """1 если смешивание скриптов"""
        import re
        cyrillic = re.findall(r'[а-яА-ЯёЁ]', url)
        latin = re.findall(r'[a-zA-Z]', url)
        return 1 if cyrillic and latin else 0
    
    def _has_rtl_override(self, url) -> int:
        """1 если RTL override символ"""
        return 1 if '\u202e' in url else 0
    
    # ============ НОВЫЕ ПРИЗНАКИ ============
    
    def _qty_percent_digits(self, url) -> float:
        """Процент цифр в URL"""
        if not url: return 0.0
        return sum(1 for c in url if c.isdigit()) / len(url)
    
    def _qty_percent_alpha(self, url) -> float:
        """Процент букв в URL"""
        if not url: return 0.0
        return sum(1 for c in url if c.isalpha()) / len(url)
    
    def _has_sensitive_words(self, url) -> int:
        """Наличие слов, связанных с безопасностью или финансами"""
        sensitive = ['password', 'card', 'billing', 'wallet', 'crypto', 'bitcoin', 'auth', 'session']
        return 1 if any(w in url.lower() for w in sensitive) else 0
    
    # ============ ОСНОВНАЯ ФУНКЦИЯ ============
    
    def extract_features(self, url: str) -> dict:
        """Извлекает все 70+ признаков из URL"""
        if not url:
            return {}
            
        if not url.startswith(('http://', 'https://')):
            url_with_scheme = 'http://' + url
        else:
            url_with_scheme = url
            
        try:
            parsed = urlparse(url_with_scheme)
        except Exception:
            parsed = urlparse("http://invalid")
        
        features = {
            # Структурные
            'url_length': self._url_length(parsed),
            'domain_length': self._domain_length(parsed),
            'subdomain_count': self._subdomain_count(parsed),
            'path_length': self._path_length(parsed),
            'query_length': self._query_length(parsed),
            'fragment_length': self._fragment_length(parsed),
            'has_ip_address': self._has_ip_address(parsed),
            'has_port': self._has_port(parsed),
            'port_number': self._port_number(parsed),
            'has_https': self._has_https(parsed),
            'has_https_in_domain': self._has_https_in_domain(url),
            'has_http_in_domain': self._has_http_in_domain(url),
            'has_url_shortener': self._has_url_shortener(parsed),
            'has_at_symbol': self._has_at_symbol(url),
            'has_double_slash_redirect': self._has_double_slash_redirect(parsed),
            'url_depth': self._url_depth(parsed),
            
            # Символьные
            'qty_dot_url': self._qty_dot_url(url),
            'qty_hyphen_url': self._qty_hyphen_url(url),
            'qty_slash_url': self._qty_slash_url(url),
            'qty_question_url': self._qty_question_url(url),
            'qty_percent_url': self._qty_percent_url(url),
            'qty_at_url': self._qty_at_url(url),
            'qty_ampersand_url': self._qty_ampersand_url(url),
            'qty_equal_url': self._qty_equal_url(url),
            'qty_underscore_url': self._qty_underscore_url(url),
            'qty_colon_url': self._qty_colon_url(url),
            'qty_semicolon_url': self._qty_semicolon_url(url),
            'qty_comma_url': self._qty_comma_url(url),
            'qty_vowels_url': self._qty_vowels_url(url),
            'qty_digits_url': self._qty_digits_url(url),
            'qty_uppercase_url': self._qty_uppercase_url(url),
            'entropy_url': self._entropy_url(url),
            'entropy_domain': self._entropy_domain(parsed),
            'qty_consecutive_dots': self._qty_consecutive_dots(url),
            
            # Доменные
            'tld_length': self._tld_length(parsed),
            'domain_extension': self._domain_extension(parsed),
            'has_common_tld': self._has_common_tld(parsed),
            'has_suspicious_tld': self._has_suspicious_tld(parsed),
            'qty_hyphens_domain': self._qty_hyphens_domain(parsed),
            'qty_underscores_domain': self._qty_underscores_domain(parsed),
            'has_multiple_domains': self._has_multiple_domains(url),
            'domain_digits_ratio': self._domain_digits_ratio(parsed),
            
            # Лексические
            'has_suspicious_keywords': self._has_suspicious_keywords(url),
            'qty_suspicious_keywords': self._qty_suspicious_keywords(url),
            'has_brand_mimicking': self._has_brand_mimicking(url),
            'qty_brand_mimicking': self._qty_brand_mimicking(url),
            'has_numeric_only_domain': self._has_numeric_only_domain(parsed),
            'has_consecutive_letters': self._has_consecutive_letters(url),
            'has_numerics_in_domain': self._has_numerics_in_domain(parsed),
            'has_repeated_subdomains': self._has_repeated_subdomains(parsed),
            'qty_slashes_path': self._qty_slashes_path(parsed),
            'qty_dots_path': self._qty_dots_path(parsed),
            'path_has_parameters': self._path_has_parameters(parsed),
            'qty_parameters': self._qty_parameters(parsed),
            'has_base64_encoding': self._has_base64_encoding(url),
            'has_hex_encoding': self._has_hex_encoding(url),
            'has_obfuscation': self._has_obfuscation(url),
            
            # Редиректы
            'has_localhost': self._has_localhost(parsed),
            'has_internal_ip': self._has_internal_ip(parsed),
            'has_suspicious_protocol': self._has_suspicious_protocol(parsed),
            'has_javascript_protocol': self._has_javascript_protocol(url),
            'has_data_protocol': self._has_data_protocol(url),
            
            # Спецсимволы
            'has_email_format': self._has_email_format(url),
            'qty_special_chars': self._qty_special_chars(url),
            'ratio_special_to_length': self._ratio_special_to_length(url),
            'has_uncommon_chars': self._has_uncommon_chars(url),
            'has_punycode': self._has_punycode(url),
            'has_unicode_chars': self._has_unicode_chars(url),
            'has_mixed_scripts': self._has_mixed_scripts(url),
            'has_rtl_override': self._has_rtl_override(url),
            
            # Новые
            'qty_percent_digits': self._qty_percent_digits(url),
            'qty_percent_alpha': self._qty_percent_alpha(url),
            'has_sensitive_words': self._has_sensitive_words(url)
        }
        
        return features
    
    def get_feature_names(self) -> list:
        """Возвращает упорядоченный список всех признаков"""
        example_features = self.extract_features('https://example.com')
        return list(example_features.keys())
    
    def extract_features_batch(self, urls: list) -> list:
        """Извлечение признаков из списка URLs"""
        return [self.extract_features(url) for url in urls]
