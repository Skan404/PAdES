
# crypto_utils.py (fragmenty do zmiany)
import os
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag # Upewnij się, że InvalidTag jest importowane

# Stałe
RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 256 # bits
AES_NONCE_SIZE = 12 # bytes (standard for GCM)
AES_TAG_SIZE = 16 # bytes (standard for GCM) # Dodano stałą dla rozmiaru tagu
HASH_ALGORITHM = hashes.SHA256()

def generate_rsa_keys():
    """Generuje parę kluczy RSA 4096 bit."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key, password=None):
    """Serializuje klucz prywatny do formatu PEM (opcjonalnie szyfrowany hasłem)."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password.encode('utf-8'))
    )
    return pem

def serialize_public_key(public_key):
    """Serializuje klucz publiczny do formatu PEM."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def load_private_key_from_pem(pem_data, password=None):
    """Wczytuje klucz prywatny z danych PEM."""
    try:
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password.encode('utf-8') if password else None,
            backend=default_backend()
        )
        return private_key
    except (ValueError, TypeError) as e:
        # ValueError może wystąpić przy złym haśle lub formacie
        # TypeError jeśli hasło jest wymagane a nie podane
        print(f"Błąd ładowania klucza prywatnego: {e}")
        return None


def load_public_key_from_pem(pem_data):
    """Wczytuje klucz publiczny z danych PEM."""
    try:
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
        return public_key
    except ValueError as e:
        print(f"Błąd ładowania klucza publicznego: {e}")
        return None


def hash_pin(pin):
    """Haszuje PIN używając SHA-256, zwraca 32 bajty (256 bitów)."""
    # UWAGA: W realnym systemie użyj PBKDF2/bcrypt/Argon2 z solą!
    return hashlib.sha256(pin.encode('utf-8')).digest()

def encrypt_aes_gcm(data, key):
    """Szyfruje dane używając AES-GCM z podanym kluczem (32 bajty).
       Zwraca (nonce, tag, ciphertext_only).""" # Zmieniono zwracane wartości
    if len(key) * 8 != AES_KEY_SIZE:
        raise ValueError(f"Klucz AES musi mieć {AES_KEY_SIZE} bitów ({AES_KEY_SIZE//8} bajtów)")

    nonce = os.urandom(AES_NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext_only = encryptor.update(data) + encryptor.finalize()
    # Pobierz tag uwierzytelniający po finalizacji
    tag = encryptor.tag
    return nonce, tag, ciphertext_only # Zwróć trzy elementy

def decrypt_aes_gcm(nonce, tag, ciphertext_only, key): # Dodano parametr 'tag'
    """Deszyfruje dane używając AES-GCM. Wymaga nonce, tagu, ciphertextu i klucza.
       Zwraca odszyfrowane dane lub None przy błędzie."""
    if len(key) * 8 != AES_KEY_SIZE:
        raise ValueError(f"Klucz AES musi mieć {AES_KEY_SIZE} bitów ({AES_KEY_SIZE//8} bajtów)")
    if len(tag) != AES_TAG_SIZE:
         raise ValueError(f"Tag uwierzytelniający musi mieć {AES_TAG_SIZE} bajtów")


    try:
        # Przekaż tag bezpośrednio do konstruktora GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        # Deszyfruj tylko właściwy ciphertext
        plaintext = decryptor.update(ciphertext_only) + decryptor.finalize()
        return plaintext
    except InvalidTag:
        print("Błąd deszyfrowania AES-GCM: Nieprawidłowy tag (zły klucz/PIN lub dane uszkodzone)")
        return None
    except Exception as e:
        print(f"Inny błąd deszyfrowania AES-GCM: {e}")
        return None


def hash_file(file_path):
    """Oblicza hash pliku używając HASH_ALGORITHM."""
    hasher = hashes.Hash(HASH_ALGORITHM, backend=default_backend())
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.finalize()
    except FileNotFoundError:
        print(f"Błąd: Plik nie znaleziony - {file_path}")
        return None
    except Exception as e:
        print(f"Błąd podczas haszowania pliku {file_path}: {e}")
        return None

def sign_rsa(private_key, data_hash):
    """Podpisuje hash danych używając klucza prywatnego RSA i PSS padding."""
    if not data_hash:
         raise ValueError("Nie można podpisać pustego hasha")
    try:
        signature = private_key.sign(
            data_hash,
            padding.PSS(
                mgf=padding.MGF1(HASH_ALGORITHM),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            HASH_ALGORITHM
        )
        return signature
    except Exception as e:
        print(f"Błąd podczas podpisywania RSA: {e}")
        return None

def verify_rsa(public_key, signature, data_hash):
    """Weryfikuje podpis RSA używając klucza publicznego i PSS padding."""
    if not data_hash or not signature:
        print("Błąd weryfikacji: Brak danych lub podpisu.")
        return False
    try:
        public_key.verify(
            signature,
            data_hash,
            padding.PSS(
                mgf=padding.MGF1(HASH_ALGORITHM),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            HASH_ALGORITHM
        )
        return True  # Podpis poprawny
    except InvalidSignature:
        print("Weryfikacja RSA: Podpis NIEPOPRAWNY.")
        return False
    except Exception as e:
        print(f"Błąd podczas weryfikacji RSA: {e}")
        return False