// Feature Extractor for Phishing URL Detection (Ported from Python)

class FeatureExtractor {
    constructor() {
        this.suspicious_keywords = [
            'login', 'verify', 'secure', 'confirm', 'account', 'update', 
            'alert', 'urgent', 'action', 'payment', 'transaction', 'click',
            'reset', 'recover', 'validate', 'authenticate', 'access', 
            'activate', 'confirm', 'password', 'change', 'immediately'
        ];
        
        this.brand_keywords = [
            'amazon', 'paypal', 'google', 'facebook', 'apple', 'microsoft',
            'netflix', 'bank', 'visa', 'mastercard', 'ebay', 'uber',
            'dropbox', 'onedrive', 'instagram', 'twitter', 'linkedin'
        ];
        
        this.suspicious_tlds = [
            'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'pw', 'top', 'men', 'download',
            'online', 'site', 'space', 'website', 'host'
        ];
        
        this.common_tlds = [
            'com', 'org', 'net', 'ru', 'us', 'uk', 'de', 'fr', 'it', 'es',
            'gov', 'edu', 'info', 'biz', 'co'
        ];
    }

    _entropy(str) {
        const len = str.length;
        if (len === 0) return 0;
        const counts = {};
        for (let i = 0; i < len; i++) {
            const c = str[i];
            counts[c] = (counts[c] || 0) + 1;
        }
        let entropy = 0;
        for (const c in counts) {
            const p = counts[c] / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    extract(urlStr) {
        let url;
        try {
            // Ensure scheme
            if (!urlStr.startsWith('http')) {
                url = new URL('http://' + urlStr);
            } else {
                url = new URL(urlStr);
            }
        } catch (e) {
            return null; // Invalid URL
        }

        const domain = url.hostname;
        const path = url.pathname;
        const query = url.search;
        const fragment = url.hash;
        
        const features = {};

        // --- Structural ---
        features['url_length'] = urlStr.length;
        features['domain_length'] = domain.length;
        // Count dots in domain minus 1 (approx subdomains if not IP)
        features['subdomain_count'] = (domain.match(/\./g) || []).length - 1;
        if (features['subdomain_count'] < 0) features['subdomain_count'] = 0;
        
        features['path_length'] = path.length;
        features['query_length'] = query.length;
        features['fragment_length'] = fragment.length;
        
        // IP check
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        features['has_ip_address'] = ipPattern.test(domain) ? 1 : 0;
        
        features['has_port'] = url.port ? 1 : 0;
        features['port_number'] = url.port ? parseInt(url.port) : -1;
        features['has_https'] = url.protocol === 'https:' ? 1 : 0;
        
        // HTTPS in domain
        features['has_https_in_domain'] = domain.includes('https') ? 1 : 0;
        features['has_http_in_domain'] = domain.includes('http') ? 1 : 0;
        
        // Shorteners
        const shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'short.link', 'lnk.co', 't.co', 'is.gd', 'cli.gs'];
        features['has_url_shortener'] = shorteners.some(s => domain.includes(s)) ? 1 : 0;
        
        features['has_at_symbol'] = urlStr.includes('@') ? 1 : 0;
        features['has_double_slash_redirect'] = path.includes('//') ? 1 : 0;
        
        // url_depth (count slashes in path)
        features['url_depth'] = (path.match(/\//g) || []).length;

        // --- Lexical & Characters ---
        const countChar = (s, c) => (s.split(c).length - 1);
        
        features['qty_dot_url'] = countChar(urlStr, '.');
        features['qty_hyphen_url'] = countChar(urlStr, '-');
        features['qty_slash_url'] = countChar(urlStr, '/');
        features['qty_question_url'] = countChar(urlStr, '?');
        features['qty_percent_url'] = countChar(urlStr, '%');
        features['qty_at_url'] = countChar(urlStr, '@');
        features['qty_ampersand_url'] = countChar(urlStr, '&');
        features['qty_equal_url'] = countChar(urlStr, '=');
        features['qty_underscore_url'] = countChar(urlStr, '_');
        features['qty_colon_url'] = countChar(urlStr, ':');
        features['qty_semicolon_url'] = countChar(urlStr, ';');
        features['qty_comma_url'] = countChar(urlStr, ',');
        
        const vowels = 'aeiouAEIOU';
        features['qty_vowels_url'] = Array.from(urlStr).filter(c => vowels.includes(c)).length;
        features['qty_digits_url'] = Array.from(urlStr).filter(c => c >= '0' && c <= '9').length;
        features['qty_uppercase_url'] = Array.from(urlStr).filter(c => c >= 'A' && c <= 'Z').length;
        
        features['entropy_url'] = this._entropy(urlStr);
        features['entropy_domain'] = this._entropy(domain);
        
        features['qty_consecutive_dots'] = (urlStr.match(/\.\./g) || []).length;

        // --- Domain ---
        const parts = domain.split('.');
        const tld = parts.length > 1 ? parts[parts.length - 1] : '';
        features['tld_length'] = tld.length;
        
        // TLD Map (simplified from python)
        const tldMap = {
            'com': 1, 'ru': 2, 'net': 3, 'org': 4, 'uk': 5,
            'de': 6, 'jp': 7, 'fr': 8, 'au': 9, 'us': 10,
            'ca': 11, 'info': 12, 'biz': 13, 'xyz': 14, 'top': 15,
            'cn': 16, 'in': 17, 'br': 18, 'io': 19, 'online': 20
        };
        features['domain_extension'] = tldMap[tld.toLowerCase()] || 0;
        
        features['has_common_tld'] = this.common_tlds.includes(tld.toLowerCase()) ? 1 : 0;
        features['has_suspicious_tld'] = this.suspicious_tlds.includes(tld.toLowerCase()) ? 1 : 0;
        
        features['qty_hyphens_domain'] = countChar(domain, '-');
        features['qty_underscores_domain'] = countChar(domain, '_');
        
        // multiple domains (http count)
        features['has_multiple_domains'] = (urlStr.match(/http/gi) || []).length > 1 ? 1 : 0;
        
        // domain digits ratio
        const domainDigits = Array.from(domain).filter(c => c >= '0' && c <= '9').length;
        const domainAlpha = Array.from(domain).filter(c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')).length;
        features['domain_digits_ratio'] = domainAlpha > 0 ? domainDigits / domainAlpha : 0;

        // --- Keywords ---
        const urlLower = urlStr.toLowerCase();
        features['has_suspicious_keywords'] = this.suspicious_keywords.some(kw => urlLower.includes(kw)) ? 1 : 0;
        features['qty_suspicious_keywords'] = this.suspicious_keywords.filter(kw => urlLower.includes(kw)).length;
        
        features['has_brand_mimicking'] = this.brand_keywords.some(kw => urlLower.includes(kw)) ? 1 : 0;
        features['qty_brand_mimicking'] = this.brand_keywords.filter(kw => urlLower.includes(kw)).length;
        
        // Numeric only domain (excluding dots)
        features['has_numeric_only_domain'] = /^\d+$/.test(domain.replace(/\./g, '')) ? 1 : 0;
        
        // Consecutive letters (3+)
        features['has_consecutive_letters'] = /(.)\1\1/.test(urlStr) ? 1 : 0;
        
        features['has_numerics_in_domain'] = /\d/.test(domain) ? 1 : 0;
        
        // Repeated subdomains
        const subs = parts.slice(0, -1);
        const uniqueSubs = new Set(subs);
        features['has_repeated_subdomains'] = subs.length !== uniqueSubs.size ? 1 : 0;
        
        features['qty_slashes_path'] = (path.match(/\//g) || []).length;
        features['qty_dots_path'] = (path.match(/\./g) || []).length;
        
        features['path_has_parameters'] = query.length > 0 ? 1 : 0;
        features['qty_parameters'] = query.length > 0 ? (query.match(/&/g) || []).length + 1 : 0;
        
        // Base64 check (rough)
        features['has_base64_encoding'] = /[A-Za-z0-9+/]{25,}={0,2}/.test(urlStr) ? 1 : 0;
        features['has_hex_encoding'] = urlStr.includes('%') ? 1 : 0;
        features['has_obfuscation'] = (features['has_base64_encoding'] || features['has_hex_encoding']) ? 1 : 0;
        
        // Redirects
        features['has_localhost'] = domain.includes('localhost') ? 1 : 0;
        // Internal IP regex
        const internalIp = /(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)/;
        features['has_internal_ip'] = internalIp.test(domain) ? 1 : 0;
        
        features['has_suspicious_protocol'] = !['http:', 'https:'].includes(url.protocol) ? 1 : 0;
        features['has_javascript_protocol'] = url.protocol === 'javascript:' ? 1 : 0;
        features['has_data_protocol'] = url.protocol === 'data:' ? 1 : 0;
        
        // Special chars
        features['has_email_format'] = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(urlStr) ? 1 : 0;
        
        const specialChars = "!@#$%^&*()_+-=[]{}|;:\",.<>?/~`";
        let qtySpecial = 0;
        for (const c of urlStr) if (specialChars.includes(c)) qtySpecial++;
        features['qty_special_chars'] = qtySpecial;
        features['ratio_special_to_length'] = urlStr.length > 0 ? qtySpecial / urlStr.length : 0;
        
        // Uncommon chars (non-ascii)
        features['has_uncommon_chars'] = /[^\x00-\x7F]/.test(urlStr) ? 1 : 0;
        features['has_punycode'] = urlStr.includes('xn--') ? 1 : 0;
        features['has_unicode_chars'] = features['has_uncommon_chars']; // same check
        
        // Mixed scripts (Cyrillic + Latin)
        const hasCyrillic = /[а-яА-ЯёЁ]/.test(urlStr);
        const hasLatin = /[a-zA-Z]/.test(urlStr);
        features['has_mixed_scripts'] = (hasCyrillic && hasLatin) ? 1 : 0;
        
        features['has_rtl_override'] = urlStr.includes('\u202e') ? 1 : 0;
        
        // New features
        features['qty_percent_digits'] = urlStr.length > 0 ? features['qty_digits_url'] / urlStr.length : 0;
        features['qty_percent_alpha'] = urlStr.length > 0 ? (urlStr.match(/[a-zA-Z]/g) || []).length / urlStr.length : 0;
        
        const sensitive = ['password', 'card', 'billing', 'wallet', 'crypto', 'bitcoin', 'auth', 'session'];
        features['has_sensitive_words'] = sensitive.some(w => urlLower.includes(w)) ? 1 : 0;

        return features;
    }

    // Returns array of feature values in correct order matching training
    getVector(urlStr) {
        const features = this.extract(urlStr);
        if (!features) return null;

        // Order MUST match Python FeatureExtractor.get_feature_names()
        // Based on src/data/feature_extractor.py
        const featureNames = [
            'url_length', 'domain_length', 'subdomain_count', 'path_length', 'query_length', 'fragment_length',
            'has_ip_address', 'has_port', 'port_number', 'has_https', 'has_https_in_domain', 'has_http_in_domain',
            'has_url_shortener', 'has_at_symbol', 'has_double_slash_redirect', 'url_depth',
            'qty_dot_url', 'qty_hyphen_url', 'qty_slash_url', 'qty_question_url', 'qty_percent_url',
            'qty_at_url', 'qty_ampersand_url', 'qty_equal_url', 'qty_underscore_url', 'qty_colon_url',
            'qty_semicolon_url', 'qty_comma_url', 'qty_vowels_url', 'qty_digits_url', 'qty_uppercase_url',
            'entropy_url', 'entropy_domain', 'qty_consecutive_dots',
            'tld_length', 'domain_extension', 'has_common_tld', 'has_suspicious_tld',
            'qty_hyphens_domain', 'qty_underscores_domain', 'has_multiple_domains', 'domain_digits_ratio',
            'has_suspicious_keywords', 'qty_suspicious_keywords', 'has_brand_mimicking', 'qty_brand_mimicking',
            'has_numeric_only_domain', 'has_consecutive_letters', 'has_numerics_in_domain', 'has_repeated_subdomains',
            'qty_slashes_path', 'qty_dots_path', 'path_has_parameters', 'qty_parameters',
            'has_base64_encoding', 'has_hex_encoding', 'has_obfuscation',
            'has_localhost', 'has_internal_ip', 'has_suspicious_protocol', 'has_javascript_protocol', 'has_data_protocol',
            'has_email_format', 'qty_special_chars', 'ratio_special_to_length', 'has_uncommon_chars',
            'has_punycode', 'has_unicode_chars', 'has_mixed_scripts', 'has_rtl_override',
            'qty_percent_digits', 'qty_percent_alpha', 'has_sensitive_words'
        ];

        const vector = featureNames.map(name => {
            const val = features[name];
            return typeof val === 'boolean' ? (val ? 1 : 0) : val;
        });

        // Convert to Float32Array for ONNX
        return new Float32Array(vector);
    }
}

// Export for usage in other modules
if (typeof module !== 'undefined') module.exports = FeatureExtractor;

