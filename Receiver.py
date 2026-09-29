import os
import json
import base64
import urllib.request
import hashlib
import hmac
import time
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.join(BASE_DIR, "shared2")
LOG_DIR = os.path.join(BASE_DIR, "logs")
RSA_DIR = os.path.join(BASE_DIR, "rsa_keys")
os.makedirs(SHARED_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(RSA_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "transactions.log")

def log_message(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

PRIVATE_KEY_FILE = os.path.join(RSA_DIR, "rsa_private.pem")
PUBLIC_KEY_FILE = os.path.join(RSA_DIR, "rsa_public.pem")

def generate_or_load_rsa_keys():
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        log_message("Existing RSA key pair found.")
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key

    log_message("RSA key pair not found.")
    log_message("Generating RSA-2048 key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_bytes)
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_bytes)
    log_message("RSA key pair generated successfully.")
    return private_key, public_key
def send_status(sender_ip, status):
    url = f"http://{sender_ip}:{PORT}/status"
    data = json.dumps({"status": status}).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()
    except Exception:
        pass

def download_text(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8")

def canonical_key(cipher, key):
    cipher = cipher.upper()
    if cipher == "CAESAR":
        return str(key)
    elif cipher == "PLAYFAIR":
        return str(key)
    elif cipher == "HILL":
        return ",".join(str(x) for x in key)
    else:
        return str(key)
def derive_hmac_key(cipher, key):
    canonical = canonical_key(cipher, key)
    material = "CNS-HMAC|" + cipher.upper() + "|" + canonical
    return hashlib.sha256(material.encode("utf-8")).digest()

def create_auth_payload(transfer_type, cipher, filename, encrypted_data):
    payload = transfer_type + "|" + cipher + "|" + filename + "|" + encrypted_data
    return payload.encode("utf-8")

def verify_authentication(transfer_type, cipher, filename, encrypted_data, key, received_tag):
    if not received_tag:
        raise PermissionError("Authentication tag missing.")
    hmac_key = derive_hmac_key(cipher, key)
    payload = create_auth_payload(transfer_type, cipher, filename, encrypted_data)
    expected_tag = hmac.new(hmac_key, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_tag, received_tag):
        raise PermissionError("Incorrect decryption key.")
    return True

def caesar_decrypt(text, key):
    result = ""
    for ch in text:
        if ch.isupper():
            result += chr((ord(ch) - 65 - key) % 26 + 65)
        elif ch.islower():
            result += chr((ord(ch) - 97 - key) % 26 + 97)
        else:
            result += ch
    return result

def generate_playfair_matrix(key):
    key = "".join(ch for ch in key.upper() if ch.isalpha())
    key = key.replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    sequence = ""
    for ch in key + alphabet:
        if ch in alphabet and ch not in sequence:
            sequence += ch
    matrix = [sequence[i:i + 5] for i in range(0, 25, 5)]
    positions = {}
    for r in range(5):
        for c in range(5):
            positions[matrix[r][c]] = (r, c)
    return matrix, positions

def playfair_decrypt(text, key):
    matrix, positions = generate_playfair_matrix(key)
    text = "".join(ch for ch in text.upper() if ch.isalpha())
    if len(text) % 2 != 0:
        raise ValueError("Invalid Playfair ciphertext.")
    result = ""
    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]
        if a not in positions or b not in positions:
            raise ValueError("Invalid Playfair ciphertext.")
        r1, c1 = positions[a]
        r2, c2 = positions[b]
        if r1 == r2:
            result += matrix[r1][(c1 - 1) % 5]
            result += matrix[r2][(c2 - 1) % 5]
        elif c1 == c2:
            result += matrix[(r1 - 1) % 5][c1]
            result += matrix[(r2 - 1) % 5][c2]
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]
    return result

def mod_inverse(a, m):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def hill_decrypt(text, key):
    text = "".join(ch for ch in text.upper() if ch.isalpha())
    if len(text) % 2 != 0:
        raise ValueError("Invalid Hill ciphertext.")
    if len(key) != 4:
        raise PermissionError("Incorrect Hill key.")
    a, b, c, d = key
    determinant = (a * d - b * c) % 26
    inverse_determinant = mod_inverse(determinant, 26)
    if inverse_determinant is None:
        raise ValueError("Invalid Hill key.")
    ia = (d * inverse_determinant) % 26
    ib = (-b * inverse_determinant) % 26
    ic = (-c * inverse_determinant) % 26
    id_ = (a * inverse_determinant) % 26
    result = ""
    for i in range(0, len(text), 2):
        x1 = ord(text[i]) - 65
        x2 = ord(text[i + 1]) - 65
        y1 = (ia * x1 + ib * x2) % 26
        y2 = (ic * x1 + id_ * x2) % 26
        result += chr(y1 + 65)
        result += chr(y2 + 65)
    return result

def letters_to_bytes(text):
    text = "".join(ch for ch in text.upper() if "A" <= ch <= "P")
    if len(text) % 2 != 0:
        raise ValueError("Invalid file ciphertext.")
    output = bytearray()
    for i in range(0, len(text), 2):
        high = ord(text[i]) - ord("A")
        low = ord(text[i + 1]) - ord("A")
        if high < 0 or high > 15 or low < 0 or low > 15:
            raise ValueError("Invalid encoded byte.")
        value = (high << 4) | low
        output.append(value)
    return bytes(output)

def decrypt_file_data(encrypted, cipher, key):
    if cipher == "CAESAR":
        decoded = caesar_decrypt(encrypted, key)
    elif cipher == "HILL":
        decoded = hill_decrypt(encrypted, key)
    elif cipher == "PLAYFAIR":
        decoded = playfair_decrypt(encrypted, key)
    else:
        raise ValueError("Unsupported file cipher.")
    return letters_to_bytes(decoded)

def rsa_decrypt_message(encrypted_text, private_key):
    try:
        encrypted_all = base64.b64decode(encrypted_text.strip())
    except Exception:
        raise ValueError("Invalid RSA encrypted data.")
    key_size_bytes = private_key.key_size // 8
    if len(encrypted_all) % key_size_bytes != 0:
        raise ValueError("Invalid RSA ciphertext length.")
    decrypted = bytearray()
    for i in range(0, len(encrypted_all), key_size_bytes):
        block = encrypted_all[i:i + key_size_bytes]
        plain = private_key.decrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted.extend(plain)
    return decrypted.decode("utf-8")
def unique_message_filename():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    candidate = os.path.join(SHARED_DIR, f"decrypted_message_{timestamp}.txt")
    counter = 1
    while os.path.exists(candidate):
        candidate = os.path.join(SHARED_DIR, f"decrypted_message_{timestamp}_{counter}.txt")
        counter += 1
    return candidate

def unique_filename(filename):
    name, ext = os.path.splitext(filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    candidate = os.path.join(SHARED_DIR, f"{name}_received_{timestamp}{ext}")
    counter = 1
    while os.path.exists(candidate):
        candidate = os.path.join(SHARED_DIR, f"{name}_received_{timestamp}_{counter}{ext}")
        counter += 1
    return candidate

def unauthorized_message():
    print()
    print("=" * 60)
    print("             UNAUTHORIZED ACCESS")
    print("=" * 60)
    print()
    print("The decryption key is incorrect.")
    print("Authentication failed.")
    print("The encrypted data was NOT decrypted.")
    print("No decrypted message/file was created.")
    print("=" * 60)

def main():
    print()
    print("=" * 60)
    print("        SECURE WI-FI MESSAGE / TXT FILE RECEIVER")
    print("=" * 60)
    print()
    print("Checking RSA key pair...")
    try:
        private_key, public_key = generate_or_load_rsa_keys()
        print("RSA system ready.")
    except Exception as e:
        print(f"RSA setup error: {e}")
        return

    print()
    print("-" * 60)
    sender_ip = input("Enter Sender IP: ").strip()
    if not sender_ip:
        print("Sender IP cannot be empty.")
        return

    base_url = f"http://{sender_ip}:{PORT}"
    info_url = base_url + "/transfer_info.json"
    data_url = base_url + "/encrypted_data.txt"
    print()
    print("Connecting to sender...")
    rsa_key_sent = False
    last_message = ""

    while True:
        try:
            info_text = download_text(info_url)
            info = json.loads(info_text)
            transfer_type = info.get("transfer_type", "")
            cipher = info.get("cipher", "")
            ready = info.get("ready", False)

            if cipher == "RSA":
                if transfer_type not in {"", "MESSAGE"}:
                    print("ERROR: RSA supports messages only.")
                    return

                if not rsa_key_sent:
                    print()
                    print("RSA transfer detected.")
                    print("Sending receiver RSA public key...")
                    with open(PUBLIC_KEY_FILE, "rb") as f:
                        public_key_pem = f.read()

                    request = urllib.request.Request(
                        base_url + "/rsa_public_key",
                        data=public_key_pem,
                        headers={"Content-Type": "application/x-pem-file"},
                        method="POST"
                    )

                    try:
                        with urllib.request.urlopen(request, timeout=10) as response:
                            response.read()
                        rsa_key_sent = True
                        print("RSA public key sent successfully.")
                        send_status(sender_ip, "RSA public key sent to sender")
                        print()
                        print("Waiting for sender to encrypt the message...")
                    except Exception as e:
                        print(f"Could not send RSA public key: {e}")
                        time.sleep(2)
                        continue

                if ready:
                    break

                time.sleep(1)
                continue

            if not ready:
                message = "Sender connected, but transfer is not ready."
                if message != last_message:
                    print(message)
                    last_message = message
                time.sleep(1)
                continue

            break

        except Exception:
            message = "Sender not ready. Retrying..."
            if message != last_message:
                print(message)
                last_message = message
            send_status(sender_ip, "Receiver attempting to connect")
            time.sleep(1)

    print()
    print("Connected successfully.")
    send_status(sender_ip, "Receiver connected")

    transfer_type = info.get("transfer_type", "")
    cipher = info.get("cipher", "")
    filename = info.get("filename", "")
    auth_tag = info.get("auth_tag", "")

    print()
    print("-" * 60)
    print("TRANSFER INFORMATION")
    print("-" * 60)
    print("Transfer Type :", transfer_type)
    print("Cipher        :", cipher)

    if transfer_type == "TXT_FILE":
        print("File Name     :", filename)

    print("-" * 60)
    print(f"\nCipher automatically detected: {cipher}")
    send_status(sender_ip, "Transfer information received")

    valid_ciphers = {"CAESAR", "PLAYFAIR", "HILL", "RSA"}

    if cipher not in valid_ciphers:
        print("\nUnknown cipher received.")
        return

    if transfer_type not in {"MESSAGE", "TXT_FILE"}:
        print("\nUnknown transfer type received.")
        return

    if cipher == "RSA" and transfer_type != "MESSAGE":
        print("\nERROR: RSA supports messages only.")
        return

    if cipher == "RSA":
        print()
        print("RSA encrypted message is ready.")

    print()
    print("Downloading encrypted data...")

    while True:
        try:
            encrypted_data = download_text(data_url)
            if encrypted_data.strip():
                break
        except Exception:
            pass
        time.sleep(1)

    print("Encrypted data received.")
    send_status(sender_ip, "Encrypted data downloaded")

    if cipher == "RSA":
        try:
            print()
            print("Using receiver's RSA private key...")
            print("Decrypting...")
            plaintext = rsa_decrypt_message(encrypted_data, private_key)
            output_file = unique_message_filename()

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(plaintext)

            print()
            print("-" * 60)
            print("DECRYPTED MESSAGE")
            print("-" * 60)
            print(plaintext)
            print("-" * 60)
            print()
            print("RSA decryption successful.")
            print(f"Saved to:\n{output_file}")
            send_status(sender_ip, "RSA decryption completed")
            send_status(sender_ip, "Message successfully received")
            return

        except Exception as e:
            print()
            print("RSA DECRYPTION ERROR:")
            print(str(e))
            log_message(f"RSA decryption failed: {e}")
            send_status(sender_ip, "RSA decryption failed")
            return

    try:
        if transfer_type == "MESSAGE":
            print()
            print("Enter decryption key.")

            if cipher == "CAESAR":
                key_text = input("Caesar key: ").strip()
                try:
                    key = int(key_text)
                except Exception:
                    raise PermissionError("Incorrect Caesar key.")
                key_for_auth = key_text

            elif cipher == "PLAYFAIR":
                key = input("Playfair key: ").strip()
                if not key or not key.isalpha():
                    raise PermissionError("Incorrect Playfair key.")
                key_for_auth = key

            elif cipher == "HILL":
                key_text = input("Hill key (a b c d): ").strip()
                try:
                    values = [int(x) for x in key_text.split()]
                except Exception:
                    raise PermissionError("Incorrect Hill key.")
                if len(values) != 4:
                    raise PermissionError("Incorrect Hill key.")
                key = values
                key_for_auth = key

            else:
                raise PermissionError("Invalid cipher.")

            print()
            print("Verifying decryption key...")
            verify_authentication(transfer_type, cipher, filename, encrypted_data, key_for_auth, auth_tag)
            print("Authentication successful.")
            print("Correct decryption key confirmed.")

            if cipher == "CAESAR":
                plaintext = caesar_decrypt(encrypted_data, key)
            elif cipher == "PLAYFAIR":
                plaintext = playfair_decrypt(encrypted_data, key)
            elif cipher == "HILL":
                plaintext = hill_decrypt(encrypted_data, key)

            output_file = unique_message_filename()

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(plaintext)

            print()
            print("-" * 60)
            print("DECRYPTED MESSAGE")
            print("-" * 60)
            print(plaintext)
            print("-" * 60)
            print()
            print("Message successfully decrypted.")
            print(f"Saved to:\n{output_file}")
            send_status(sender_ip, "Decryption completed")
            send_status(sender_ip, "Message successfully received")

        elif transfer_type == "TXT_FILE":
            if cipher == "CAESAR":
                key_text = input("\nCaesar key: ").strip()
                try:
                    key = int(key_text)
                except Exception:
                    raise PermissionError("Incorrect Caesar key.")
                key_for_auth = key_text

            elif cipher == "PLAYFAIR":
                key = input("\nPlayfair key: ").strip()
                if not key or not key.isalpha():
                    raise PermissionError("Incorrect Playfair key.")
                key_for_auth = key

            elif cipher == "HILL":
                key_text = input("\nHill key (a b c d): ").strip()
                try:
                    key = [int(x) for x in key_text.split()]
                except Exception:
                    raise PermissionError("Incorrect Hill key.")
                if len(key) != 4:
                    raise PermissionError("Incorrect Hill key.")
                key_for_auth = key

            else:
                raise PermissionError("RSA cannot be used for files.")

            print()
            print("Verifying decryption key...")
            verify_authentication(transfer_type, cipher, filename, encrypted_data, key_for_auth, auth_tag)
            print("Authentication successful.")
            print("Correct decryption key confirmed.")
            print()
            print("Decrypting file...")
            file_data = decrypt_file_data(encrypted_data, cipher, key)
            output_file = unique_filename(filename)

            with open(output_file, "wb") as f:
                f.write(file_data)

            print()
            print("File decryption completed.")
            print(f"Saved to:\n{output_file}")
            send_status(sender_ip, "File decryption completed")
            send_status(sender_ip, "File successfully received")

        else:
            raise ValueError("Unknown transfer type.")

    except PermissionError as e:
        unauthorized_message()
        log_message("UNAUTHORIZED ACCESS - " + str(e))
        send_status(sender_ip, "Unauthorized access - incorrect key")

    except Exception as e:
        print()
        print("DECRYPTION ERROR:")
        print(str(e))
        print()
        print("Please check:")
        print("1. Correct sender")
        print("2. Complete transfer")
        print("3. Correct transfer information")
        log_message(f"Decryption failed: {e}")
        send_status(sender_ip, "Decryption failed")

if __name__ == "__main__":
    main()