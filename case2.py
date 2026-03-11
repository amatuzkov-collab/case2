import base64
import re
import codecs

def find_and_validate_credit_cards(text):
    """
    Находит номера карт и проверяет по алгоритму Луна.
    Возвращает: {'valid': [], 'invalid': []}
    """
    # Ищем последовательности из 16 цифр (с любыми разделителями)
    card_pattern = r'\b(?:\d[ -]*?){13,19}\d\b'
    matches = re.findall(card_pattern, text)
    
    # Очищаем от нецифровых символов
    cleaned_cards = [re.sub(r'\D', '', match) for match in matches]
    cleaned_cards = [card for card in cleaned_cards if len(card) == 16]

    def luhn_check(card_number):
        digits = [int(d) for d in card_number]
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    result = {'valid': [], 'invalid': []}
    for card in cleaned_cards:
        if luhn_check(card):
            result['valid'].append(card)
        else:
            result['invalid'].append(card)

    return result



def find_secrets(text):
    """
    Ищет API-ключи, пароли, токены.
    Возвращает: список найденных секретов
    """
    secrets = []

    # Stripe API keys
    stripe_live = re.findall(r'sk_live_[a-zA-Z0-9_]{24,}', text)
    stripe_test = re.findall(r'sk_test_[a-zA-Z0-9_]{24,}', text)
    secrets.extend(stripe_live + stripe_test)

    # Пароли: длина >=8, есть цифры и спецсимволы
    password_pattern = r'\b(?=.*[!@#$%^&*(),.?":{}|<>])(?=.*\d)[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}\b'
    passwords = re.findall(password_pattern, text)
    # Исключим слишком простые совпадения
    passwords = [p for p in passwords if not p.isalpha() and not p.isdigit()]
    secrets.extend(passwords)

    # JWT-токены (упрощённо)
    jwt_pattern = r'ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
    jwts = re.findall(jwt_pattern, text)
    secrets.extend(jwts)

    # Приватные ключи (PEM)
    pem_keys = re.findall(r'-----BEGIN [A-Z ]+PRIVATE KEY-----.+?-----END [A-Z ]+PRIVATE KEY-----', text, re.DOTALL)
    secrets.extend(pem_keys)

    return list(set(secrets))  # Убираем дубли



def find_system_info(text):
    """
    Ищет IP, файлы, email.
    Возвращает: {'ips': [], 'files': [], 'emails': []}
    """
    result = {
        'ips': [],
        'files': [],
        'emails': []
    }

    # IPv4 адреса
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, text)
    valid_ips = [ip for ip in ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
    result['ips'] = list(set(valid_ips))

    # Email
    email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    result['emails'] = list(set(re.findall(email_pattern, text)))

    # Файлы: имена с расширениями
    file_pattern = r'\b[a-zA-Z0-9_\-\.]+\.(?:log|txt|csv|json|xml|pdf|docx|exe|bat|sh|pem|key)\b'
    result['files'] = list(set(re.findall(file_pattern, text)))

    return result


def decode_messages(text):
    """
    Находит и расшифровывает Base64, Hex, ROT13.
    Возвращает: {'base64': [], 'hex': [], 'rot13': []}
    """
    result = {'base64': [], 'hex': [], 'rot13': []}

    # Base64
    b64_pattern = r'([A-Za-z0-9+/]{20,}={0,2})'
    for candidate in re.findall(b64_pattern, text):
        try:
            decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
            if len(decoded) > 2 and all(ord(c) >= 32 or ord(c) == 10 for c in decoded):
                result['base64'].append(decoded.strip())
        except:
            pass

    # Hex чистый bytes.fromhex без каких либо зависимостей
    hex_patterns = [
        r'0x([A-Fa-f0-9]{4,})',
        r'(?:\\x[0-9A-Fa-f]{2})+'
    ]

    for h in re.findall(hex_patterns[0], text):
        try:
            decoded = bytes.fromhex(h).decode('utf-8', errors='ignore')
            if decoded.strip():
                result['hex'].append(decoded.strip())
        except:
            pass

    for seq in re.findall(hex_patterns[1], text):
        try:
            clean = seq.replace('\\x', '')
            decoded = bytes.fromhex(clean).decode('utf-8', errors='ignore')
            if decoded.strip():
                result['hex'].append(decoded.strip())
        except:
            pass

    # ROT13
    for word in set(re.findall(r'[a-zA-Z]{8,}', text)):
        decoded = codecs.encode(word, 'rot13')
        if 'password' in decoded.lower() or 'secret' in decoded.lower():
            result['rot13'].append(decoded)

    # Уникальные значения
    for k in result:
        result[k] = list(set(result[k]))

    return result



def analyze_logs(log_text):
    """
    Анализирует логи веб-сервера.
    Возвращает: {sql_injections, xss_attempts, suspicious_user_agents, failed_logins}
    """
    lines = log_text.strip().split('\n')
    result = {
        'sql_injections': [],
        'xss_attempts': [],
        'suspicious_user_agents': [],
        'failed_logins': []
    }

    sql_pattern = r"(?:'|--|\bOR\b|\bUNION\b).*?(?:=|>|<)"
    xss_pattern = r"<script[^>]*?>.*?</script>|<.*?on\w+=|&#x?[\dA-F]+;"
    login_paths = ["/login", "/admin", "/auth", "/signin"]

    for line in lines:
        ip_match = re.match(r'([\d\.]+)', line)
        ip = ip_match.group(1) if ip_match else "unknown"

        # SQL Injection
        if re.search(sql_pattern, line, re.IGNORECASE):
            result['sql_injections'].append({'ip': ip, 'line': line.strip()})

        # XSS
        if re.search(xss_pattern, line, re.IGNORECASE):
            result['xss_attempts'].append({'ip': ip, 'line': line.strip()})

        # Failed login (401)
        if '" 401 ' in line or '/login' in line.lower() and 'POST' in line and '200' not in line:
            result['failed_logins'].append({'ip': ip, 'line': line.strip()})

        # Подозрительные User-Agent
        ua_match = re.search(r'"([^"]*?)"$', line)
        if ua_match:
            ua = ua_match.group(1)
            if 'EvilBot' in ua or 'sqlmap' in ua or 'nikto' in ua or 'burp' in ua.lower():
                result['suspicious_user_agents'].append({'ip': ip, 'user_agent': ua})

    return result




def normalize_and_validate(text):
    """
    Нормализует телефоны, даты, ИНН, карты.
    Возвращает: {'phones': {}, 'dates': {}, 'inn': {}, 'cards': {}}
    """
    result = {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []},
        'cards': {'valid': [], 'invalid': []}
    }

    # === Телефоны ===
    phone_pattern = r'(?:\+7|8)[\-\s\(]?\d{3}[\-\s\)]?\d{3}[\-\s]?\d{2}[\-\s]?\d{2}'
    for p in re.findall(phone_pattern, text):
        cleaned = re.sub(r'\D', '', p)
        if len(cleaned) == 11:
            normalized = f'+7{cleaned[1:]}'
            result['phones']['valid'].append(normalized)
        else:
            result['phones']['invalid'].append(p)

    months = {
        'jan': '01', 'feb': '02', 'mar': '03', 'apr': '04', 'may': '05', 'jun': '06',
        'jul': '07', 'aug': '08', 'sep': '09', 'oct': '10', 'nov': '11', 'dec': '12'
    }

    # dd.mm.yyyy
    for d, m, y in re.findall(r'\b(\d{2})\.(\d{2})\.(\d{4})\b', text):
        if 1 <= int(m) <=12 and 1 <= int(d) <=31:
            result['dates']['normalized'].append(f"{y}-{m}-{d}")

    # yyyy/mm/dd
    for y, m, d in re.findall(r'\b(\d{4})/(\d{2})/(\d{2})\b', text):
        if 1 <= int(m) <=12 and 1 <= int(d) <=31:
            result['dates']['normalized'].append(f"{y}-{m}-{d}")

    # dd-Mon-yyyy
    for d, mon, y in re.findall(r'\b(\d{1,2})-([A-Za-z]{3})-(\d{4})\b', text, re.IGNORECASE):
        mon_num = months.get(mon.lower())
        if mon_num and 1 <= int(d) <=31:
            result['dates']['normalized'].append(f"{y}-{mon_num}-{d.zfill(2)}")

    #  ИНН 
    for inn in re.findall(r'\b\d{10,12}\b', text):
        if len(inn) in (10, 12) and inn.isdigit():
            result['inn']['valid'].append(inn)
        else:
            result['inn']['invalid'].append(inn)

    #  Карты 
    result['cards'] = find_and_validate_credit_cards(text)

    # Убираем дубли
    for section in result.values():
        for key in section:
            section[key] = list(set(section[key]))

    return result