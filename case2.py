# operation_data_shield.py

import re
import base64
import codecs


# Здесь команда размещает все функции
def generate_comprehensive_report(main_text, log_text, messy_data):
    """ Генерирует полный отчет о расследовании """
    report = { 'financial_data': find_and_validate_credit_cards(main_text),
               'secrets': find_secrets(main_text),
               'system_info': find_system_info(main_text),
               'encoded_messages': decode_messages(main_text),
               'security_threats': analyze_logs(log_text),
               'normalized_data': normalize_and_validate(messy_data)
               }
    return report


def find_and_validate_credit_cards(main_text):
    def luhn_check(card_number):
        card_number = re.sub('\D', '', card_number)
        if len(card_number) != 16:
            return False

        total = 0
        for index, digit in enumerate(reversed(card_number)):
            dig = int(digit)
            if index % 2 == 1:
                dig *= 2
                if dig > 9:
                    dig -= 9
            total += dig

        return total % 10 == 0

    result = {'valid' : [], 'invalid' : []}
    card_pattern = r'\b(?:\d[ -]*?){16}\b'
    potential_cards = re.findall(card_pattern, main_text)
    for card in set(potential_cards):
        clean_card = re.sub('-\s', '', card)
        if luhn_check(clean_card):
            result['valid'].append(clean_card)
        else:
            result['invalid'].append(clean_card)

    return result


def find_secrets(main_text)


# Здесь команда размещает все функции
def generate_comprehensive_report(main_text, log_text, messy_data):
    """ Генерирует полный отчет о расследовании """
    report = { 'financial_data': find_and_validate_credit_cards(main_text),
               'secrets': find_secrets(main_text),
               'system_info': find_system_info(main_text),
               'encoded_messages': decode_messages(main_text),
               'security_threats': analyze_logs(log_text),
               'normalized_data': normalize_and_validate(messy_data)
               }
    return report


def find_and_validate_credit_cards(main_text):
    def luhn_check(card_number):
        card_number = re.sub('\D', '', card_number)
        if len(card_number) != 16:
            return False

        total = 0
        for index, digit in enumerate(reversed(card_number)):
            dig = int(digit)
            if index % 2 == 1:
                dig *= 2
                if dig > 9:
                    dig -= 9
            total += dig

        return total % 10 == 0

    result = {'valid' : [], 'invalid' : []}
    card_pattern = r'\b(?:\d[ -]*?){16}\b'
    potential_cards = re.findall(card_pattern, main_text)

    for card in set(potential_cards):
        clean_card = re.sub('\D', '', card)
        if luhn_check(clean_card):
            result['valid'].append(clean_card)
        else:
            result['invalid'].append(clean_card)

    return result


def find_secrets(main_text):
    secrets = []

    api_pattern = (r'\b(?:sk_live_|pk_live_|sk_test_|pk_test_|'
                   r'rk_live_|_rk_live_|ghp_)[a-zA-Z0-9_\-]{16,}\b'
                   )
    api_keys = re.findall(api_pattern, main_text)
    secrets.extend(api_keys)

    passwords = re.findall(
        r'(?:пароль|password)[:\s]*([A-Za-z0-9!@#$%^&*]{12,})',
        main_text,
        re.IGNORECASE
    )
    secrets.extend(passwords)

    words = main_text.split()
    for word in words:
        clean_word = word.strip('.,:;!?"\'()[]{}<>')

        if len(clean_word) >= 12:
            if (re.search(r'[A-Za-z]', clean_word) and
                    re.search(r'\d', clean_word) and
                    re.search(r'[!@#$%^&*()_+={}\[\]:;"\'<>,.?/~`|\\-]', clean_word)):
                secrets.append(clean_word)

    return list(set(secrets))


def find_system_info(main_text):
    result = {
        'ips': [],
        'emails': [],
        'files': []
    }
    
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ips = re.findall(ip_pattern, main_text)

    for ip in ips:
        parts = ip.split('.')
        valid = True
        for part in parts:
            if int(part) > 255:
                valid = False
                break
        if valid:
            result['ips'].append(ip)

    email_pattern = r'\b[\w.-]+@[\w.-]+\.\w+\b'
    result['emails'] = re.findall(email_pattern, main_text)

    file_pattern = r'\b[\w\-]+\.(?:txt|pdf|jpg|png|py|js|html|css|log)\b'
    result['files'] = re.findall(file_pattern, main_text)

    return result


from typing import List, Dict
import re, base64, codecs


def decode_messages(file: str) -> Dict[str, List[str]]:
    """
    Finds and decrypts messages
    Returns: {'base64': [], 'hex': [], 'rot13': []}
    """

    mask_1 = r'[A-Za-z0-9+/]+[=]{1,2}'

    base64_strings = re.findall(mask_1, file)
    base64_decoded = []

    for message in base64_strings:
        if len(message) % 4 == 0:
            base64message = base64.b64decode(message).decode('utf-8')
            base64_decoded.append(base64message)


    mask_2 = r'0x[A-Fa-f0-9]+'

    hex_strings = re.findall(mask_2, file)
    hex_decoded = []

    for message in hex_strings:
        hex_message = codecs.decode(message[2:], 'hex').decode('utf-8')
        hex_decoded.append(hex_message)

    mask_3 = r'\$[A-Za-z\s]+\$'

    rot13_strings = re.findall(mask_3, file)
    rot13_decoded = []

    for message in rot13_strings:
        rot13_message = codecs.decode(message, 'rot13')
        rot13_decoded.append(rot13_message.replace('$', ''))

    return {
        'base64': base64_decoded,
        'hex': hex_decoded,
        'rot13': rot13_decoded
           }


def normalize_and_validate(file: str) -> Dict[str, Dict[str, list]]:
    """ Brings the data to a single format and verifies it
        Returns:  { 'phones': {'valid': [], 'invalid': []},
                    'dates': {'normalized': [], 'invalid': []},
                    'inn': {'valid': [], 'invalid': []},
                    'cards': {'valid': [], 'invalid': []} } """

    valid_phones = []
    pattern_1 = r'[+]?[78][- ]?\d{3}[- ]?\d{3}[- ]?\d{2}[- ]?\d{2}'
    invalid_phones = re.findall(pattern_1, file)

    for phone in invalid_phones:
        valid_phones.append(re.sub(r'\D', '', phone))

    for index in range(len(valid_phones)):
        valid_phones[index] = ('+' + valid_phones[index][0] + '(' + valid_phones[index][1:4] + ')'
                               + valid_phones[index][4:7] + '-'
                               + valid_phones[index][7:9] + '-' + valid_phones[index][9:11])

    pattern_2 = r'(?:\d{2}[-/.]\d{2}[-/.]\d{2,4})|(?:\d{4}[/.-]\d{2}[/.-]\d{2})'
    normalized_dates = invalid_dates = re.findall(pattern_2, file)

    pattern_3 = r'(?:\b\d{10}\b)|(?:\b\d{12}\b)'
    valid_inn = invalid_inn = re.findall(pattern_3, file)

    valid_cards = []
    pattern_4 = r'\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}'
    invalid_cards = set(re.findall(pattern_4, file))

    for card in invalid_cards:
        valid_cards.append(re.sub(r'\D', '', card))

    for index in range(len(valid_cards)):
        valid_cards[index] = (valid_cards[index][:4] + '-' + valid_cards[index][4:8] + '-' +
                              valid_cards[index][8:12] + '-' + valid_cards[index][12:16])

    return {
        'phones': {'valid': valid_phones, 'invalid': invalid_phones},
        'dates': {'normalized': normalized_dates, 'invalid': invalid_dates},
        'inn': {'valid': valid_inn, 'invalid': invalid_inn},
        'cards': {'valid': valid_cards, 'invalid': invalid_cards}
           }