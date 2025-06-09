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


RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 256 # liczba bitów
AES_NONCE_SIZE = 12
AES_TAG_SIZE = 16
HASH_ALGORITHM = hashes.SHA256()

#generowanie kluczy RSA
def generate_rsa_keys():
    """Generuje parę kluczy RSA 4096 bit."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

#serializacja do zapisu w pem
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


#hashowanie PIN-u
# Używamy SHA-256 do haszowania PIN-u, aby uzyskać 32 bajty (256 bitów)
def hash_pin(pin):
    """Haszuje PIN używając SHA-256, zwraca 32 bajty (256 bitów)."""
    return hashlib.sha256(pin.encode('utf-8')).digest()

# Szyfrowanie i deszyfrowanie AES-GCM
def encrypt_aes_gcm(data, key):
    """Szyfruje dane używając AES-GCM z podanym kluczem (32 bajty).
       Zwraca (nonce, tag, ciphertext_only)."""
    if len(key) * 8 != AES_KEY_SIZE:
        raise ValueError(f"Klucz AES musi mieć {AES_KEY_SIZE} bitów ({AES_KEY_SIZE//8} bajtów)")

    nonce = os.urandom(AES_NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext_only = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return nonce, tag, ciphertext_only

def decrypt_aes_gcm(nonce, tag, ciphertext_only, key):
    """Deszyfruje dane używając AES-GCM. Wymaga nonce, tagu, ciphertextu i klucza.
       Zwraca odszyfrowane dane lub None przy błędzie."""
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

# Haszowanie pliku - oblicza skrót pliku przy użyciu algorytmu SHA-256
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

def hash_pdf_content(pdf_path):
    """Oblicza skrót z treści stron pliku PDF, ignorując metadane."""
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
        return True # Podpis poprawny
    except InvalidSignature:
        print("Weryfikacja RSA: Podpis NIEPOPRAWNY.")
        return False # Podpis niepoprawny
    except Exception as e:
        print(f"Błąd podczas weryfikacji RSA: {e}")
        return False # Inny błąd
    

def create_self_signed_cert(private_key, public_key, subject_name="PAdES Emulation User"):
        """Tworzy prosty samopodpisany certyfikat X.509 dla danej pary kluczy."""

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"PL"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Pomorskie"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Gdansk"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"PG Student Project"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])

        # Certyfikat ważny przez 1 rok
        one_year = datetime.timedelta(days=365)
        now = datetime.datetime.now(datetime.timezone.utc)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(public_key)
    
        builder = builder.serial_number(x509.random_serial_number()) # Numer seryjny - unikalny losowe bajty
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

        # Podpisz certyfikat kluczem prywatnym
        certificate = builder.sign(private_key, HASH_ALGORITHM, default_backend())

        return certificate

def serialize_certificate(certificate):
    """Serializuje certyfikat do formatu PEM."""
    pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
    return pem

def load_certificate_from_pem(pem_data):
    """Wczytuje certyfikat z danych PEM."""
    try:
        certificate = x509.load_pem_x509_certificate(pem_data, default_backend())
        return certificate
    except ValueError as e:
        print(f"Błąd ładowania certyfikatu: {e}")
        return None