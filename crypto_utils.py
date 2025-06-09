## @file crypto_utils.py
## @brief Moduł narzędziowy do obsługi kryptografii dla projektu PAdES.

import os
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from pypdf import PdfReader


## @var RSA_KEY_SIZE
## @brief Rozmiar klucza RSA w bitach. Używany do generacji klucza RSA.
RSA_KEY_SIZE = 4096

## @var AES_KEY_SIZE
## @brief Rozmiar klucza AES w bitach (256 = AES-256). Używany do szyfrowania klucza prywatnego.
AES_KEY_SIZE = 256

## @var AES_NONCE_SIZE
## @brief Rozmiar nonce (liczba bajtów) dla trybu AES-GCM.
AES_NONCE_SIZE = 12

## @var AES_TAG_SIZE
## @brief Rozmiar tagu uwierzytelniającego (liczba bajtów) dla trybu AES-GCM.
AES_TAG_SIZE = 16

## @var HASH_ALGORITHM
## @brief Algorytm haszowania używany w całym projekcie (SHA-256).
HASH_ALGORITHM = hashes.SHA256()

## @brief Generuje parę kluczy RSA 4096 bit.
## @return private_key, public_key
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

## @brief Serializuje klucz prywatny do formatu PEM (opcjonalnie szyfrowany hasłem).
## @param private_key Klucz prywatny RSA.
## @param password Opcjonalne hasło do szyfrowania PEM.
## @return PEM jako bytes.
def serialize_private_key(private_key, password=None):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password.encode('utf-8'))
    )
    return pem

## @brief Serializuje klucz publiczny do formatu PEM.
## @param public_key Klucz publiczny RSA.
## @return PEM jako bytes.
def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

## @brief Wczytuje klucz prywatny z danych PEM.
## @param pem_data Dane PEM.
## @param password Hasło do PEM (opcjonalnie).
## @return Klucz prywatny RSA lub None przy błędzie.
def load_private_key_from_pem(pem_data, password=None):
    try:
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password.encode('utf-8') if password else None,
            backend=default_backend()
        )
        return private_key
    except (ValueError, TypeError) as e:
        print(f"Błąd ładowania klucza prywatnego: {e}")
        return None

## @brief Wczytuje klucz publiczny z danych PEM.
## @param pem_data Dane PEM.
## @return Klucz publiczny RSA lub None przy błędzie.
def load_public_key_from_pem(pem_data):
    try:
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
        return public_key
    except ValueError as e:
        print(f"Błąd ładowania klucza publicznego: {e}")
        return None


## @brief Haszuje PIN używając SHA-256.
## @param pin PIN użytkownika jako string.
## @return Hash PIN-u (32 bajty).
def hash_pin(pin):
    return hashlib.sha256(pin.encode('utf-8')).digest()

## @brief Szyfruje dane używając AES-GCM.
## @param data Dane do zaszyfrowania.
## @param key Klucz AES (32 bajty).
## @return nonce, tag, ciphertext_only
def encrypt_aes_gcm(data, key):
    if len(key) * 8 != AES_KEY_SIZE:
        raise ValueError(f"Klucz AES musi mieć {AES_KEY_SIZE} bitów ({AES_KEY_SIZE//8} bajtów)")

    nonce = os.urandom(AES_NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext_only = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return nonce, tag, ciphertext_only

## @brief Deszyfruje dane używając AES-GCM.
## @param nonce Nonce AES-GCM.
## @param tag Tag uwierzytelniający.
## @param ciphertext_only Zaszyfrowane dane.
## @param key Klucz AES (32 bajty).
## @return Odszyfrowane dane lub None przy błędzie.
def decrypt_aes_gcm(nonce, tag, ciphertext_only, key):
    if len(key) * 8 != AES_KEY_SIZE:
        raise ValueError(f"Klucz AES musi mieć {AES_KEY_SIZE} bitów ({AES_KEY_SIZE//8} bajtów)")
    if len(tag) != AES_TAG_SIZE:
         raise ValueError(f"Tag uwierzytelniający musi mieć {AES_TAG_SIZE} bajtów")

    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext_only) + decryptor.finalize()
        return plaintext
    except InvalidTag:
        print("Błąd deszyfrowania AES-GCM: Nieprawidłowy tag (zły klucz/PIN lub dane uszkodzone)")
        return None
    except Exception as e:
        print(f"Inny błąd deszyfrowania AES-GCM: {e}")
        return None

## @brief Oblicza hash pliku używając SHA-256.
## @param file_path Ścieżka do pliku.
## @return Hash pliku jako bytes.
def hash_file(file_path):
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

## @brief Oblicza hash zawartości PDF (bez metadanych).
## @param pdf_path Ścieżka do pliku PDF.
## @return Hash zawartości PDF jako bytes.
def hash_pdf_content(pdf_path):
    try:
        reader = PdfReader(pdf_path)
        digest = hashes.Hash(HASH_ALGORITHM, backend=default_backend())
        for page in reader.pages:
            # Pobieramy surowe bajty zawartości strony
            digest.update(page.get_contents().get_data())
        return digest.finalize()
    except FileNotFoundError:
        print(f"Błąd: Plik nie znaleziony - {pdf_path}")
        return None
    except Exception as e:
        print(f"Błąd podczas haszowania zawartości PDF {pdf_path}: {e}")
        return None

## @brief Podpisuje hash danych używając RSA i PSS padding.
## @param private_key Klucz prywatny RSA.
## @param data_hash Hash danych do podpisania.
## @return Podpis (bytes) lub None przy błędzie.
def sign_rsa(private_key, data_hash):
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

## @brief Weryfikuje podpis RSA.
## @param public_key Klucz publiczny RSA.
## @param signature Podpis RSA.
## @param data_hash Hash podpisanych danych.
## @return True jeśli poprawny podpis, False w przeciwnym razie.
def verify_rsa(public_key, signature, data_hash):
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
        return True # Podpis poprawny
    except InvalidSignature:
        print("Weryfikacja RSA: Podpis NIEPOPRAWNY.")
        return False # Podpis niepoprawny
    except Exception as e:
        print(f"Błąd podczas weryfikacji RSA: {e}")
        return False # Inny błąd
    
## @brief Tworzy samopodpisany certyfikat X.509.
## @param private_key Klucz prywatny RSA.
## @param public_key Klucz publiczny RSA.
## @param subject_name Nazwa subskrybenta certyfikatu.
## @return Certyfikat X.509.
def create_self_signed_cert(private_key, public_key, subject_name="PAdES Emulation User"):

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"PL"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Pomorskie"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Gdansk"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"PG Student Project"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])

        one_year = datetime.timedelta(days=365)
        now = datetime.datetime.now(datetime.timezone.utc)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(public_key)
    
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + one_year)

        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False, data_encipherment=False,
                content_commitment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False
            ), critical=True
        )

        certificate = builder.sign(private_key, HASH_ALGORITHM, default_backend())

        return certificate

## @brief Serializuje certyfikat do formatu PEM.
## @param certificate Certyfikat X.509.
## @return Certyfikat w formacie PEM.
def serialize_certificate(certificate):
    pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
    return pem

## @brief Wczytuje certyfikat z danych PEM.
## @param pem_data Dane PEM.
## @return Certyfikat X.509 lub None przy błędzie.
def load_certificate_from_pem(pem_data):
    try:
        certificate = x509.load_pem_x509_certificate(pem_data, default_backend())
        return certificate
    except ValueError as e:
        print(f"Błąd ładowania certyfikatu: {e}")
        return None