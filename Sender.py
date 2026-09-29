import os
import json
import base64
import socket
import threading
import time
import hmac
import hashlib
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from math import gcd
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.join(BASE_DIR, 'shared')
LOG_DIR = os.path.join(BASE_DIR, 'logs')
INFO_FILE = os.path.join(SHARED_DIR, 'transfer_info.json')
DATA_FILE = os.path.join(SHARED_DIR, 'encrypted_data.txt')
LOG_FILE = os.path.join(LOG_DIR, 'sender.log')
os.makedirs(SHARED_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
rsa_public_key_event = threading.Event()
received_rsa_public_key = None

def log_message(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f'[{timestamp}] {message}'
    print(line)
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception:
        pass

def record_receiver_status(status):
    log_message(f'Receiver: {status}')

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return '127.0.0.1'

def clean_old_transfer():
    for path in [INFO_FILE, DATA_FILE]:
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            log_message(f'Warning: Could not remove old file {path}: {e}')

def initialize_transfer_info():
    info = {'ready': False, 'transfer_type': '', 'cipher': '', 'filename': '', 'authentication': '', 'auth_tag': ''}
    with open(INFO_FILE, 'w', encoding='utf-8') as f:
        json.dump(info, f, indent=4)

def canonical_key(cipher, key):
    cipher = cipher.upper()
    if cipher == 'CAESAR':
        return str(key)
    elif cipher == 'PLAYFAIR':
        return str(key)
    elif cipher == 'HILL':
        return ','.join((str(x) for x in key))
    else:
        return str(key)

def derive_hmac_key(cipher, key):
    canonical = canonical_key(cipher, key)
    material = 'CNS-HMAC|' + cipher.upper() + '|' + canonical
    return hashlib.sha256(material.encode('utf-8')).digest()

def create_auth_payload(transfer_type, cipher, filename, encrypted_data):
    payload = transfer_type + '|' + cipher + '|' + filename + '|' + encrypted_data
    return payload.encode('utf-8')

def generate_auth_tag(transfer_type, cipher, filename, encrypted_data, key):
    hmac_key = derive_hmac_key(cipher, key)
    payload = create_auth_payload(transfer_type, cipher, filename, encrypted_data)
    return hmac.new(hmac_key, payload, hashlib.sha256).hexdigest()

def caesar_encrypt(text, shift):
    result = []
    for char in text:
        if char.isupper():
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        elif char.islower():
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def create_playfair_matrix(key):
    key = key.upper().replace('J', 'I')
    characters = []
    for char in key:
        if char.isalpha() and char not in characters:
            characters.append(char)
    for char in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if char not in characters:
            characters.append(char)
    return [characters[i:i + 5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return (row, col)
    raise ValueError(f'Character {char} not found in Playfair matrix.')

def prepare_playfair_text(text):
    text = ''.join((char for char in text.upper() if char.isalpha()))
    text = text.replace('J', 'I')
    prepared = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i + 1]
            if a == b:
                prepared.append(a)
                prepared.append('X')
                i += 1
            else:
                prepared.append(a)
                prepared.append(b)
                i += 2
        else:
            prepared.append(a)
            prepared.append('X')
            i += 1
    return ''.join(prepared)

def playfair_encrypt(text, key):
    matrix = create_playfair_matrix(key)
    text = prepare_playfair_text(text)
    result = []
    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)
        if r1 == r2:
            result.append(matrix[r1][(c1 + 1) % 5])
            result.append(matrix[r2][(c2 + 1) % 5])
        elif c1 == c2:
            result.append(matrix[(r1 + 1) % 5][c1])
            result.append(matrix[(r2 + 1) % 5][c2])
        else:
            result.append(matrix[r1][c2])
            result.append(matrix[r2][c1])
    return ''.join(result)

def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if a * x % m == 1:
            return x
    raise ValueError('Matrix determinant has no modular inverse.')

def generate_hill_key():
    return [3, 3, 2, 5]

def hill_encrypt(text, key):
    text = ''.join((char for char in text.upper() if char.isalpha()))
    while len(text) % 2 != 0:
        text += 'X'
    a, b, c, d = key
    result = []
    for i in range(0, len(text), 2):
        x = ord(text[i]) - ord('A')
        y = ord(text[i + 1]) - ord('A')
        p1 = (a * x + b * y) % 26
        p2 = (c * x + d * y) % 26
        result.append(chr(p1 + ord('A')))
        result.append(chr(p2 + ord('A')))
    return ''.join(result)

def bytes_to_letters(data):
    return ''.join((chr((byte >> 4) + ord('A')) + chr((byte & 15) + ord('A')) for byte in data))

def letters_to_bytes(text):
    text = ''.join((char for char in text.upper() if 'A' <= char <= 'P'))
    if len(text) % 2 != 0:
        raise ValueError('Invalid encrypted file data.')
    data = bytearray()
    for i in range(0, len(text), 2):
        high = ord(text[i]) - ord('A')
        low = ord(text[i + 1]) - ord('A')
        data.append(high << 4 | low)
    return bytes(data)

def playfair_encrypt_file(data, key):
    letters = bytes_to_letters(data)
    return playfair_encrypt(letters, key)

def encrypt_file_data(data, cipher, key):
    if cipher == 'CAESAR':
        letters = bytes_to_letters(data)
        return caesar_encrypt(letters, key)
    elif cipher == 'PLAYFAIR':
        return playfair_encrypt_file(data, key)
    elif cipher == 'HILL':
        letters = bytes_to_letters(data)
        return hill_encrypt(letters, key)
    else:
        raise ValueError('Unsupported file cipher.')

def rsa_encrypt_message(message, public_key):
    if isinstance(message, str):
        message = message.encode('utf-8')
    encrypted_chunks = []
    max_chunk = 190
    for i in range(0, len(message), max_chunk):
        chunk = message[i:i + max_chunk]
        encrypted = public_key.encrypt(chunk, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        encrypted_chunks.append(encrypted)
    return base64.b64encode(b''.join(encrypted_chunks)).decode('utf-8')

def write_transfer_info(transfer_type, cipher, filename='', ready=True, auth_tag=''):
    if cipher == 'RSA':
        authentication = 'RSA-OAEP'
    else:
        authentication = 'HMAC-SHA256'
    info = {'ready': ready, 'transfer_type': transfer_type, 'cipher': cipher, 'filename': filename, 'authentication': authentication, 'auth_tag': auth_tag}
    with open(INFO_FILE, 'w', encoding='utf-8') as f:
        json.dump(info, f, indent=4)

class TransferHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        global received_rsa_public_key
        if self.path == '/transfer_info.json':
            try:
                with open(INFO_FILE, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                self.send_error(404, 'Transfer information not available.')
        elif self.path == '/encrypted_data.txt':
            try:
                with open(DATA_FILE, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                self.send_error(404, 'Encrypted data not available.')
        else:
            self.send_error(404, 'Not Found')

    def do_POST(self):
        global received_rsa_public_key
        if self.path == '/status':
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                status = body.decode('utf-8', errors='replace')
                record_receiver_status(status)
                self.send_response(200)
                self.end_headers()
            except Exception as e:
                log_message(f'Error receiving receiver status: {e}')
                self.send_error(400)
        elif self.path == '/rsa_public_key':
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                received_rsa_public_key = serialization.load_pem_public_key(body)
                rsa_public_key_event.set()
                log_message('Receiver RSA public key received.')
                self.send_response(200)
                self.end_headers()
            except Exception as e:
                log_message(f'RSA public key error: {e}')
                self.send_error(400)
        else:
            self.send_error(404, 'Not Found')

def start_server():
    server = HTTPServer(('0.0.0.0', PORT), TransferHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

def save_encrypted_data(encrypted_data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        f.write(encrypted_data)

def main():
    global received_rsa_public_key
    print()
    print('=' * 60)
    print('        SECURE WI-FI MESSAGE / TXT FILE SENDER')
    print('=' * 60)
    print()
    clean_old_transfer()
    initialize_transfer_info()
    server = start_server()
    local_ip = get_local_ip()
    print('Server started successfully.')
    print()
    print('Sender IP :', local_ip)
    print('Port      :', PORT)
    print()
    while True:
        print('Choose transfer type:')
        print('1. Message')
        print('2. .txt File')
        choice = input('\nEnter choice: ').strip()
        if choice == '1':
            transfer_type = 'MESSAGE'
            break
        elif choice == '2':
            transfer_type = 'TXT_FILE'
            break
        else:
            print('Please enter 1 or 2.')
            print()
    while True:
        print()
        print('Choose cipher:')
        print('1. Caesar')
        print('2. Playfair')
        print('3. Hill')
        print('4. RSA')
        cipher_choice = input('\nEnter cipher choice: ').strip()
        cipher_map = {'1': 'CAESAR', '2': 'PLAYFAIR', '3': 'HILL', '4': 'RSA'}
        if cipher_choice not in cipher_map:
            print('Please enter a number from 1 to 4.')
            continue
        cipher = cipher_map[cipher_choice]
        if transfer_type == 'TXT_FILE' and cipher == 'RSA':
            print()
            print('RSA supports MESSAGE only.')
            print('Please choose Caesar, Vigenere, Playfair or Hill for a .txt file.')
            continue
        break
    print()
    print('=' * 60)
    print('TRANSFER SETUP')
    print('=' * 60)
    print('Transfer Type :', transfer_type)
    print('Cipher        :', cipher)
    print('=' * 60)
    print()
    if cipher == 'RSA':
        print('Waiting for receiver RSA public key...')
        write_transfer_info('MESSAGE', 'RSA', '', ready=False, auth_tag='')
        while not rsa_public_key_event.is_set():
            time.sleep(0.5)
        print('Receiver RSA public key received.')
        message = input('\nEnter message: ')
        encrypted_data = rsa_encrypt_message(message, received_rsa_public_key)
        save_encrypted_data(encrypted_data)
        write_transfer_info('MESSAGE', 'RSA', '', ready=True, auth_tag='')
        print()
        print('RSA message encrypted successfully.')
        print('Waiting for receiver...')
        print()
    elif transfer_type == 'MESSAGE':
        if cipher == 'CAESAR':
            while True:
                key_input = input('\nEnter Caesar key (number): ').strip()
                try:
                    key = int(key_input)
                    key_for_auth = key_input
                    break
                except ValueError:
                    print('Please enter a valid number.')
        elif cipher == 'PLAYFAIR':
            while True:
                key = input('\nEnter Playfair key: ').strip()
                if key and key.isalpha():
                    key_for_auth = key
                    break
                print('Playfair key must contain letters only.')
        elif cipher == 'HILL':
            key = generate_hill_key()
            key_for_auth = key
            print('\nGenerated Hill key:')
            print(f'{key[0]} {key[1]} {key[2]} {key[3]}')
        message = input('\nEnter message: ')
        if cipher == 'CAESAR':
            encrypted_data = caesar_encrypt(message, key)
        elif cipher == 'PLAYFAIR':
            encrypted_data = playfair_encrypt(message, key)
        elif cipher == 'HILL':
            encrypted_data = hill_encrypt(message, key)
        auth_tag = generate_auth_tag('MESSAGE', cipher, '', encrypted_data, key_for_auth)
        save_encrypted_data(encrypted_data)
        write_transfer_info('MESSAGE', cipher, '', ready=True, auth_tag=auth_tag)
        print()
        print('=' * 60)
        print('MESSAGE READY')
        print('=' * 60)
        print('Transfer Type : MESSAGE')
        print('Cipher        :', cipher)
        print('Authentication: HMAC-SHA256')
        if cipher == 'HILL':
            print('Key           :', f'{key[0]} {key[1]} {key[2]} {key[3]}')
        else:
            print('Key           :', key)
        print('Encrypted data ready.')
        print('=' * 60)
        print()
    elif transfer_type == 'TXT_FILE':
        while True:
            file_path = input('\nEnter .txt file path: ').strip()
            if not file_path:
                print('File path cannot be empty.')
                continue
            if not os.path.isfile(file_path):
                print('File does not exist.')
                continue
            if not file_path.lower().endswith('.txt'):
                print('Only .txt files are supported.')
                continue
            break
        filename = os.path.basename(file_path)
        with open(file_path, 'rb') as f:
            file_data = f.read()
        if cipher == 'CAESAR':
            while True:
                key_input = input('\nEnter Caesar key (number): ').strip()
                try:
                    key = int(key_input)
                    key_for_auth = key_input
                    break
                except ValueError:
                    print('Please enter a valid number.')
        elif cipher == 'PLAYFAIR':
            while True:
                key = input('\nEnter Playfair key: ').strip()
                if key and key.isalpha():
                    key_for_auth = key
                    break
                print('Playfair key must contain letters only.')
        elif cipher == 'HILL':
            key = generate_hill_key()
            key_for_auth = key
            print('\nGenerated Hill key:')
            print(f'{key[0]} {key[1]} {key[2]} {key[3]}')
        encrypted_data = encrypt_file_data(file_data, cipher, key)
        auth_tag = generate_auth_tag('TXT_FILE', cipher, filename, encrypted_data, key_for_auth)
        save_encrypted_data(encrypted_data)
        write_transfer_info('TXT_FILE', cipher, filename, ready=True, auth_tag=auth_tag)
        print()
        print('=' * 60)
        print('TXT FILE READY')
        print('=' * 60)
        print('Transfer Type : TXT_FILE')
        print('File Name     :', filename)
        print('Cipher        :', cipher)
        print('Authentication: HMAC-SHA256')
        if cipher == 'HILL':
            print('Key           :', f'{key[0]} {key[1]} {key[2]} {key[3]}')
        else:
            print('Key           :', key)
        print('Encrypted file data ready.')
        print('=' * 60)
        print()
    print('Waiting for receiver...')
    print('Press Ctrl+C to stop the sender.')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        print('Stopping sender...')
        try:
            server.shutdown()
        except Exception:
            pass
if __name__ == '__main__':
    main()
