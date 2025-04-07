import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import time
import datetime # Potrzebne do certyfikatu
import crypto_utils
import drive_utils

# Importy PyHanko - z poprawionym PdfStamper
try:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    
    from pyhanko.stamp import PdfStamper # <-- POPRAWIONY IMPORT
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko.sign.validation.errors import SignatureValidationError
    from pyhanko.sign.general import UnacceptableSignerError
    from pyhanko.sign.signers.pdf_signer import PreSignValidationStatus
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    PYHANKO_AVAILABLE = True
except ImportError as e:
    print("="*30)
    print(f" UWAGA: Błąd podczas importowania PyHanko lub jego zależności!")
    print(f" SZCZEGÓŁY BŁĘDU: {e}")
    print(" Funkcjonalność podpisywania/weryfikacji PDF może nie działać.")
    print(" Sprawdź instalację PyHanko i jego zależności.")
    print(" Możesz spróbować: python -m pip install --upgrade --force-reinstall pyhanko")
    print("="*30)
    PYHANKO_AVAILABLE = False


class SignVerifyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Podpisywanie i Weryfikacja PDF (PyHanko) - BSK")
        self.geometry("650x600")

        # Style
        style = ttk.Style(self)
        style.configure('TButton', padding=6); style.configure('TLabel', padding=2); style.configure('TEntry', padding=4)
        style.configure('Status.TLabel', font=('Helvetica', 10, 'italic'))
        style.configure('Success.Status.TLabel', foreground='green'); style.configure('Error.Status.TLabel', foreground='red'); style.configure('Info.Status.TLabel', foreground='blue')

        # Zmienne stanu
        self.pdf_to_sign_path = tk.StringVar(); self.pdf_to_verify_path = tk.StringVar()
        self.public_key_path_verify = tk.StringVar(); self.encrypted_key_path = tk.StringVar()

        # Notebook
        self.notebook = ttk.Notebook(self)
        self.sign_frame = ttk.Frame(self.notebook, padding="10"); self.verify_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.sign_frame, text='Podpisywanie Dokumentu PDF'); self.notebook.add(self.verify_frame, text='Weryfikacja Podpisu PDF')
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # Zakładki i Logi
        self._create_sign_widgets(); self._create_verify_widgets(); self._create_log_area()

        # Sprawdzanie pendrive'a
        if PYHANKO_AVAILABLE:
             self.check_pendrive(); self.after(5000, self.check_pendrive_periodically)
        else:
             self.log_message("PyHanko NIEDOSTĘPNE. Aplikacja ograniczona.", "ERROR")
             messagebox.showerror("Brak Biblioteki", "Biblioteka PyHanko nie jest zainstalowana.\nZainstaluj ją ('pip install pyhanko'), aby włączyć podpisywanie/weryfikację PDF.")

    # --- METODY WEWNĄTRZ KLASY ---

    def _create_log_area(self):
        ttk.Label(self, text="Logi aplikacji:").pack(pady=(5,0))
        self.log_text = scrolledtext.ScrolledText(self, height=8, width=80, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(padx=10, pady=5, expand=True, fill=tk.BOTH)

    def log_message(self, message, level="INFO"):
        self.log_text.config(state=tk.NORMAL); timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp} {level}] {message}\n"); self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED); self.update_idletasks()

    def set_status(self, label_widget, message, level="info"):
        label_widget.config(text=message)
        style_map = {"success": 'Success.Status.TLabel', "error": 'Error.Status.TLabel', "info": 'Info.Status.TLabel'}
        label_widget.config(style=style_map.get(level, 'Status.TLabel'))
        self.log_message(message, level.upper())

    def check_pendrive(self):
        key_path = drive_utils.find_key_on_removable_drives()
        if key_path:
            self.encrypted_key_path.set(key_path)
            self.set_status(self.pendrive_status_label, f"OK: Znaleziono klucz: {key_path}", "success")
            return True
        else:
            self.encrypted_key_path.set("")
            if hasattr(self, 'pendrive_status_label'):
                 self.set_status(self.pendrive_status_label, "BŁĄD: Nie znaleziono pliku 'private_key.enc'.", "error")
            return False

    def check_pendrive_periodically(self):
        self.check_pendrive(); self.after(5000, self.check_pendrive_periodically)

    def select_pdf_to_sign(self):
        path = filedialog.askopenfilename(title="Wybierz PDF do podpisania", filetypes=[("PDF files", "*.pdf")])
        if path: self.pdf_to_sign_path.set(path); self.log_message(f"Wybrano plik do podpisania: {path}")

    def select_pdf_to_verify(self):
        path = filedialog.askopenfilename(title="Wybierz PODPISANY plik PDF", filetypes=[("PDF files", "*.pdf")])
        if path: self.pdf_to_verify_path.set(path); self.log_message(f"Wybrano plik PDF do weryfikacji: {path}")

    def select_public_key_for_verify(self):
        path = filedialog.askopenfilename(title="Wybierz klucz publiczny (.pem) Opcjonalnie", filetypes=[("PEM files", "*.pem")])
        if path: self.public_key_path_verify.set(path); self.log_message(f"Wybrano klucz publiczny do weryfikacji: {path}")

    def _create_sign_widgets(self):
        frame = self.sign_frame; row = 0
        ttk.Label(frame, text="1. Wybierz plik PDF do podpisania:").grid(row=row, column=0, sticky=tk.W, pady=2); row += 1
        ttk.Entry(frame, textvariable=self.pdf_to_sign_path, width=60, state='readonly').grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=(0, 5))
        ttk.Button(frame, text="Przeglądaj...", command=self.select_pdf_to_sign).grid(row=row, column=2, sticky=tk.W); row += 1
        ttk.Label(frame, text="2. Status klucza prywatnego na Pendrive:").grid(row=row, column=0, sticky=tk.W, pady=(10, 2)); row += 1
        self.pendrive_status_label = ttk.Label(frame, text="Oczekiwanie...", style='Info.Status.TLabel', width=60)
        self.pendrive_status_label.grid(row=row, column=0, columnspan=3, sticky=tk.W); row += 1
        ttk.Label(frame, text="3. Wprowadź PIN do klucza prywatnego:").grid(row=row, column=0, sticky=tk.W, pady=(10, 2)); row += 1
        self.pin_entry_sign = ttk.Entry(frame, show="*", width=30); self.pin_entry_sign.grid(row=row, column=0, columnspan=3, sticky=tk.W); row += 1
        ttk.Label(frame, text="4. Metadane podpisu (opcjonalne):").grid(row=row, column=0, sticky=tk.W, pady=(10, 2)); row += 1
        ttk.Label(frame, text="   Powód:").grid(row=row, column=0, sticky=tk.W)
        self.sign_reason_entry = ttk.Entry(frame, width=40); self.sign_reason_entry.grid(row=row, column=1, columnspan=2, sticky=tk.W); self.sign_reason_entry.insert(0, "Akceptacja dokumentu"); row += 1
        ttk.Label(frame, text="   Lokalizacja:").grid(row=row, column=0, sticky=tk.W)
        self.sign_location_entry = ttk.Entry(frame, width=40); self.sign_location_entry.grid(row=row, column=1, columnspan=2, sticky=tk.W); self.sign_location_entry.insert(0, "Gdansk, Polska"); row += 1
        sign_button = ttk.Button(frame, text="Podpisz Dokument PDF", command=self.sign_document, state=tk.NORMAL if PYHANKO_AVAILABLE else tk.DISABLED) # Poprawna komenda
        sign_button.grid(row=row, column=0, columnspan=3, pady=20); row += 1
        ttk.Label(frame, text="Status operacji:").grid(row=row, column=0, sticky=tk.W, pady=(10, 2)); row += 1
        self.sign_status_label = ttk.Label(frame, text="-", style='Status.TLabel', width=70); self.sign_status_label.grid(row=row, column=0, columnspan=3, sticky=tk.W)

    def _create_verify_widgets(self):
        frame = self.verify_frame; row = 0
        ttk.Label(frame, text="1. Wybierz PODPISANY plik PDF:").grid(row=row, column=0, sticky=tk.W, pady=2); row += 1
        ttk.Entry(frame, textvariable=self.pdf_to_verify_path, width=60, state='readonly').grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=(0, 5))
        ttk.Button(frame, text="Przeglądaj...", command=self.select_pdf_to_verify).grid(row=row, column=2, sticky=tk.W); row += 1
        ttk.Label(frame, text="2. Klucz publiczny (.pem) do ręcznej weryfikacji (Opcjonalne):").grid(row=row, column=0, sticky=tk.W, pady=(10, 2)); row += 1
        ttk.Entry(frame, textvariable=self.public_key_path_verify, width=60, state='readonly').grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=(0, 5))
        ttk.Button(frame, text="Przeglądaj...", command=self.select_public_key_for_verify).grid(row=row, column=2, sticky=tk.W); row += 1
        verify_button = ttk.Button(frame, text="Weryfikuj Podpis(y) w PDF", command=self.verify_signature, state=tk.NORMAL if PYHANKO_AVAILABLE else tk.DISABLED) # Poprawna komenda
        verify_button.grid(row=row, column=0, columnspan=3, pady=20); row += 1
        ttk.Label(frame, text="Status operacji:").grid(row=row, column=0, sticky=tk.W, pady=(10, 2)); row += 1
        self.verify_status_label = ttk.Label(frame, text="-", style='Status.TLabel', width=70); self.verify_status_label.grid(row=row, column=0, columnspan=3, sticky=tk.W)

    # ---------------------------------------------------------------
    # TUTAJ ZACZYNAJĄ SIĘ DEFINICJE METOD sign_document i verify_signature
    # MUSZĄ BYĆ WEWNĄTRZ KLASY (mieć wcięcie jak inne metody)
    # ---------------------------------------------------------------

    def sign_document(self):
        """Logika podpisywania dokumentu z użyciem PyHanko (metoda PdfStamper)."""
        if not PYHANKO_AVAILABLE: messagebox.showerror("Błąd", "Biblioteka PyHanko nie jest zainstalowana."); return
        self.set_status(self.sign_status_label, "Rozpoczynanie podpisywania...", "info")
        pdf_path_in = self.pdf_to_sign_path.get(); key_file = self.encrypted_key_path.get(); pin = self.pin_entry_sign.get()
        if not pdf_path_in or not os.path.isfile(pdf_path_in): self.set_status(self.sign_status_label, "BŁĄD: Wybierz PDF.", "error"); return
        if not key_file: self.set_status(self.sign_status_label, "BŁĄD: Brak klucza.", "error"); return
        if len(pin) < 4: self.set_status(self.sign_status_label, "BŁĄD: PIN za krótki.", "error"); return
        private_key = None
        try:
            self.set_status(self.sign_status_label, "Odczytywanie i deszyfrowanie klucza...", "info")
            with open(key_file, 'rb') as f: nonce = f.read(crypto_utils.AES_NONCE_SIZE); tag = f.read(crypto_utils.AES_TAG_SIZE); encrypted_pem_only = f.read()
            if len(nonce) != crypto_utils.AES_NONCE_SIZE or len(tag) != crypto_utils.AES_TAG_SIZE: self.set_status(self.sign_status_label, "BŁĄD: Plik klucza uszkodzony.", "error"); return
            aes_key = crypto_utils.hash_pin(pin)
            decrypted_pem = crypto_utils.decrypt_aes_gcm(nonce, tag, encrypted_pem_only, aes_key)
            if decrypted_pem is None: self.set_status(self.sign_status_label, "BŁĄD: Deszyfrowanie nie powiodło się.", "error"); return
            private_key = serialization.load_pem_private_key(decrypted_pem, password=None, backend=crypto_utils.default_backend())
            public_key = private_key.public_key()
            self.set_status(self.sign_status_label, "Klucz prywatny załadowany.", "info")
            self.set_status(self.sign_status_label, "Generowanie certyfikatu samopodpisanego...", "info")
            signing_cert = crypto_utils.create_self_signed_cert(private_key, public_key)
            self.log_message(f"Certyfikat wygenerowany dla: {signing_cert.subject.rfc4514_string()}")
            signer = signers.SimpleSigner(signing_key=private_key, signing_cert=signing_cert, cert_registry=None)
            meta = signers.PdfSignatureMetadata(reason=self.sign_reason_entry.get() or None, location=self.sign_location_entry.get() or None, sign_time=datetime.datetime.now(datetime.timezone.utc))
            pdf_path_out_default = os.path.splitext(pdf_path_in)[0] + "_signed.pdf"
            pdf_path_out = filedialog.asksaveasfilename( title="Zapisz podpisany PDF jako...", initialfile=os.path.basename(pdf_path_out_default), initialdir=os.path.dirname(pdf_path_in), defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
            if not pdf_path_out: self.set_status(self.sign_status_label, "Anulowano zapis.", "info"); return
            self.set_status(self.sign_status_label, f"Podpisywanie pliku (Stamper): {os.path.basename(pdf_path_in)}...", "info")
            stamper = PdfStamper(meta)
            with open(pdf_path_in, 'rb') as inf, open(pdf_path_out, 'wb') as outf:
                stamper.sign(pdf_out=outf, pdf_in=inf, signer=signer)
            self.set_status(self.sign_status_label, f"SUKCES: Dokument PDF podpisany! Zapisano w: {pdf_path_out}", "success")
            messagebox.showinfo("Podpisano Pomyślnie", f"Plik PDF został podpisany cyfrowo.\nZapisano jako:\n{pdf_path_out}")
        except (FileNotFoundError, ValueError, TypeError, UnacceptableSignerError, SignatureValidationError) as e:
             error_msg = f"BŁĄD: {type(e).__name__} - {e}"; self.set_status(self.sign_status_label, error_msg , "error"); self.log_message(f"Szczegóły błędu: {e}", level="ERROR"); messagebox.showerror("Błąd Podpisywania", f"Wystąpił błąd:\n{e}")
        except Exception as e:
             error_msg = f"BŁĄD KRYTYCZNY: {type(e).__name__} - {e}"; self.set_status(self.sign_status_label, error_msg, "error"); self.log_message(f"Szczegóły błędu: {e}", level="ERROR"); messagebox.showerror("Błąd Krytyczny", f"Wystąpił nieoczekiwany błąd:\n{e}")

    def verify_signature(self):
        """Logika weryfikacji podpisu(ów) w pliku PDF z użyciem PyHanko."""
        if not PYHANKO_AVAILABLE: messagebox.showerror("Błąd", "Biblioteka PyHanko nie jest zainstalowana."); return
        self.set_status(self.verify_status_label, "Rozpoczynanie weryfikacji...", "info")
        pdf_path = self.pdf_to_verify_path.get(); pubkey_pem_path = self.public_key_path_verify.get()
        if not pdf_path or not os.path.isfile(pdf_path): self.set_status(self.verify_status_label, "BŁĄD: Wybierz poprawny, podpisany plik PDF.", "error"); return
        validation_summary = []
        try:
            r = PdfFileReader(pdf_path)
            if not r.embedded_signatures:
                 self.set_status(self.verify_status_label, "Informacja: Nie znaleziono podpisów.", "info"); messagebox.showinfo("Brak Podpisów", "W pliku PDF nie znaleziono podpisów."); return
            self.log_message(f"Znaleziono {len(r.embedded_signatures)} podpis(ów).")
            for ix, emb_sig in enumerate(r.embedded_signatures):
                 sig_name = emb_sig.field_name or f"Podpis #{ix+1}"; self.log_message(f"--- Weryfikacja: {sig_name} ---")
                 try: # Sprawdzenie integralności
                     integrity_info = emb_sig.compute_integrity_info()
                     if integrity_info.valid: self.log_message(f"[{sig_name}] Integralność: POPRAWNA"); validation_summary.append(f"{sig_name}: Integralność OK")
                     else: self.log_message(f"[{sig_name}] Integralność: BŁĘDNA ({integrity_info.modification_info})", "ERROR"); validation_summary.append(f"{sig_name}: INTEGRALNOŚĆ NARUSZONA!")
                 except Exception as e: self.log_message(f"[{sig_name}] Błąd integralności: {e}", "ERROR"); validation_summary.append(f"{sig_name}: Błąd integralności")
                 public_key_to_use = None; signer_cert = emb_sig.signer_cert
                 if signer_cert: self.log_message(f"[{sig_name}] Certyfikat w podpisie: CN={signer_cert.subject.rfc4514_string()}"); public_key_to_use = signer_cert.public_key()
                 elif pubkey_pem_path and os.path.isfile(pubkey_pem_path):
                     self.log_message(f"[{sig_name}] Brak certyfikatu. Użycie klucza z pliku: {pubkey_pem_path}")
                     try:
                          with open(pubkey_pem_path, 'rb') as f_pub: pubkey_pem_data = f_pub.read()
                          public_key_to_use = crypto_utils.load_public_key_from_pem(pubkey_pem_data)
                          if public_key_to_use is None: self.log_message(f"[{sig_name}] Nie załadowano klucza z {pubkey_pem_path}", "ERROR")
                     except Exception as e: self.log_message(f"[{sig_name}] Błąd odczytu pliku klucza: {e}", "ERROR")
                 else: self.log_message(f"[{sig_name}] Brak certyfikatu i pliku klucza.", "WARNING")
                 if public_key_to_use: # Weryfikacja kryptograficzna
                     try:
                          signed_data = emb_sig.signed_data; signature_bytes = emb_sig.signature
                          # Uproszczone haszowanie - zakładamy SHA256 jak w HASH_ALGORITHM
                          actual_hash = crypto_utils.HASH_ALGORITHM.hash_func(signed_data).digest()
                          self.log_message(f"[{sig_name}] Hash danych: {actual_hash.hex()}")
                          self.log_message(f"[{sig_name}] Podpis (frag.): {signature_bytes[:16].hex()}...")
                          is_math_valid = crypto_utils.verify_rsa(public_key_to_use, signature_bytes, actual_hash)
                          if is_math_valid: self.log_message(f"[{sig_name}] Weryfikacja kryptograficzna: POPRAWNA", "SUCCESS"); validation_summary.append(f"{sig_name}: Podpis OK")
                          else: self.log_message(f"[{sig_name}] Weryfikacja kryptograficzna: BŁĘDNA", "ERROR"); validation_summary.append(f"{sig_name}: PODPIS NIEZGODNY!")
                     except Exception as e: self.log_message(f"[{sig_name}] Błąd weryfikacji kryptograf.: {e}", "ERROR"); validation_summary.append(f"{sig_name}: Błąd weryfikacji")
                 else: validation_summary.append(f"{sig_name}: Brak klucza")
            final_message = f"Weryfikacja {len(r.embedded_signatures)} podpis(ów):\n" + "\n".join(validation_summary)
            all_ok = all("OK" in s or "Brak klucza" in s for s in validation_summary)
            if all_ok and any("OK" in s for s in validation_summary):
                 self.set_status(self.verify_status_label, f"Weryfikacja OK ({len(validation_summary)} el.). Szczegóły w logach.", "success"); messagebox.showinfo("Weryfikacja Zakończona", final_message)
            else:
                 self.set_status(self.verify_status_label, f"Weryfikacja Zakończona z problemami. Szczegóły w logach.", "error"); messagebox.showwarning("Weryfikacja Zakończona", final_message)
        except Exception as e:
            error_msg = f"BŁĄD KRYTYCZNY weryfikacji: {type(e).__name__} - {e}"; self.set_status(self.verify_status_label, error_msg, "error"); self.log_message(f"Szczegóły błędu: {e}", level="ERROR"); messagebox.showerror("Błąd Krytyczny", f"Wystąpił nieoczekiwany błąd:\n{e}")

# --- Główny blok uruchomieniowy ---
if __name__ == "__main__":
    if not PYHANKO_AVAILABLE: print("\nProszę zainstalować PyHanko i uruchomić aplikację ponownie.")
    app = SignVerifyApp()
    app.mainloop()