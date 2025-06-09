## @file sign_verify_app.py
## @brief Główna aplikacja GUI do podpisywania i weryfikacji PDF dla projektu BSK.
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import time
import crypto_utils
import drive_utils

## @var PYPDF_AVAILABLE
## @brief Czy biblioteka pypdf jest dostępna (True/False).
try:
    from pypdf import PdfReader, PdfWriter
    PYPDF_AVAILABLE = True
except ImportError as e:
    print("="*30)
    print(f" UWAGA: Błąd podczas importowania PyPDF lub jego zależności!")
    print(f" SZCZEGÓŁY BŁĘDU: {e}")
    print("="*30)
    PYPDF_AVAILABLE = False

## @class SignVerifyApp
## @brief Główna klasa aplikacji GUI do podpisywania i weryfikacji PDF.
## Dziedziczy po tkinter.Tk.
class SignVerifyApp(tk.Tk):
    
    ## @brief Inicjalizacja głównego okna aplikacji i komponentów GUI.
    def __init__(self):
        super().__init__()
        self.title("Podpisywanie i Weryfikacja PDF - BSK")
        self.geometry("650x600")

        style = ttk.Style(self)
        style.configure('TButton', padding=6); style.configure('TLabel', padding=2); style.configure('TEntry', padding=4)
        style.configure('Status.TLabel', font=('Helvetica', 10, 'italic'))
        style.configure('Success.Status.TLabel', foreground='green'); style.configure('Error.Status.TLabel', foreground='red'); style.configure('Info.Status.TLabel', foreground='blue')

        self.pdf_to_sign_path = tk.StringVar(); self.pdf_to_verify_path = tk.StringVar()
        self.public_key_path_verify = tk.StringVar(); self.encrypted_key_path = tk.StringVar()

        self.notebook = ttk.Notebook(self)
        self.sign_frame = ttk.Frame(self.notebook, padding="10"); self.verify_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.sign_frame, text='Podpisywanie Dokumentu PDF'); self.notebook.add(self.verify_frame, text='Weryfikacja Podpisu PDF')
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        self._create_sign_widgets(); self._create_verify_widgets(); self._create_log_area()

        if PYPDF_AVAILABLE:
             self.check_pendrive(); self.after(5000, self.check_pendrive_periodically)
        else:
             self.log_message("PyPDF NIEDOSTĘPNE. Aplikacja ograniczona.", "ERROR")
             messagebox.showerror("Brak Biblioteki", "Biblioteka pypdf nie jest zainstalowana.\nZainstaluj ją ('pip install pypdf'), aby włączyć podpisywanie/weryfikację PDF.")

    ## @brief Tworzy obszar logów (ScrolledText).
    def _create_log_area(self):
        ttk.Label(self, text="Logi aplikacji:").pack(pady=(5,0))
        self.log_text = scrolledtext.ScrolledText(self, height=8, width=80, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(padx=10, pady=5, expand=True, fill=tk.BOTH)

    ## @brief Dodaje wiadomość do logów.
    ## @param message Tekst wiadomości.
    ## @param level Poziom logowania (INFO, ERROR, SUCCESS itp.).
    def log_message(self, message, level="INFO"):
        self.log_text.config(state=tk.NORMAL); timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp} {level}] {message}\n"); self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED); self.update_idletasks()
        
    ## @brief Ustawia tekst i styl etykiety statusu.
    ## @param label_widget Etykieta do zmiany.
    ## @param message Tekst statusu.
    ## @param level Poziom statusu (info, success, error).
    def set_status(self, label_widget, message, level="info"):
        label_widget.config(text=message)
        style_map = {"success": 'Success.Status.TLabel', "error": 'Error.Status.TLabel', "info": 'Info.Status.TLabel'}
        label_widget.config(style=style_map.get(level, 'Status.TLabel'))
        self.log_message(message, level.upper())

    ## @brief Sprawdza obecność pendrive i klucza prywatnego.
    ## @return True jeśli znaleziono, False w przeciwnym razie.
    def check_pendrive(self):
        key_path = drive_utils.find_key_on_removable_drives()
        if key_path:
            self.encrypted_key_path.set(key_path)
            self.set_status(self.pendrive_status_label, f"OK: Znaleziono klucz: {key_path}", "success")
            return True
        else:
            self.encrypted_key_path.set("")
            if hasattr(self, 'pendrive_status_label'):
                 self.set_status(self.pendrive_status_label, f"BŁĄD: Nie znaleziono pliku '{drive_utils.KEY_FILENAME}'.", "error")
            return False

    ## @brief Okresowo sprawdza obecność pendrive co 5 sekund.
    def check_pendrive_periodically(self):
        self.check_pendrive(); self.after(5000, self.check_pendrive_periodically)

    ## @brief Okno dialogowe do wyboru pliku PDF do podpisania.
    def select_pdf_to_sign(self):
        path = filedialog.askopenfilename(title="Wybierz PDF do podpisania", filetypes=[("PDF files", "*.pdf")])
        if path: self.pdf_to_sign_path.set(path); self.log_message(f"Wybrano plik do podpisania: {path}")

    ## @brief Okno dialogowe do wyboru pliku PDF do weryfikacji.
    def select_pdf_to_verify(self):
        path = filedialog.askopenfilename(title="Wybierz PODPISANY plik PDF", filetypes=[("PDF files", "*.pdf")])
        if path: self.pdf_to_verify_path.set(path); self.log_message(f"Wybrano plik PDF do weryfikacji: {path}")

    ## @brief Okno dialogowe do wyboru klucza publicznego PEM do weryfikacji.
    def select_public_key_for_verify(self):
        path = filedialog.askopenfilename(title="Wybierz klucz publiczny (.pem) Opcjonalnie", filetypes=[("PEM files", "*.pem")])
        if path: self.public_key_path_verify.set(path); self.log_message(f"Wybrano klucz publiczny do weryfikacji: {path}")

    ## @brief Tworzy komponenty GUI dla zakładki podpisywania dokumentu.
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
        
        sign_button = ttk.Button(frame, text="Podpisz Dokument PDF", command=self.sign_document, state=tk.NORMAL if PYPDF_AVAILABLE else tk.DISABLED)
        sign_button.grid(row=row, column=0, columnspan=3, pady=20); row += 1

        ttk.Label(frame, text="Status operacji:").grid(row=row, column=0, sticky=tk.W, pady=(10, 2)); row += 1
        self.sign_status_label = ttk.Label(frame, text="-", style='Status.TLabel', width=70); self.sign_status_label.grid(row=row, column=0, columnspan=3, sticky=tk.W)

    ## @brief Tworzy komponenty GUI dla zakładki weryfikacji podpisu.
    def _create_verify_widgets(self):
        frame = self.verify_frame; row = 0
        ttk.Label(frame, text="1. Wybierz PODPISANY plik PDF:").grid(row=row, column=0, sticky=tk.W, pady=2); row += 1
        ttk.Entry(frame, textvariable=self.pdf_to_verify_path, width=60, state='readonly').grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=(0, 5))
        ttk.Button(frame, text="Przeglądaj...", command=self.select_pdf_to_verify).grid(row=row, column=2, sticky=tk.W); row += 1
        ttk.Label(frame, text="2. Klucz publiczny (.pem) do ręcznej weryfikacji (Opcjonalne):").grid(row=row, column=0, sticky=tk.W, pady=(10, 2)); row += 1
        ttk.Entry(frame, textvariable=self.public_key_path_verify, width=60, state='readonly').grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=(0, 5))
        ttk.Button(frame, text="Przeglądaj...", command=self.select_public_key_for_verify).grid(row=row, column=2, sticky=tk.W); row += 1
        verify_button = ttk.Button(frame, text="Weryfikuj Podpis w PDF", command=self.verify_signature, state=tk.NORMAL if PYPDF_AVAILABLE else tk.DISABLED)
        verify_button.grid(row=row, column=0, columnspan=3, pady=20); row += 1
        ttk.Label(frame, text="Status operacji:").grid(row=row, column=0, sticky=tk.W, pady=(10, 2)); row += 1
        self.verify_status_label = ttk.Label(frame, text="-", style='Status.TLabel', width=70); self.verify_status_label.grid(row=row, column=0, columnspan=3, sticky=tk.W)


    ## @brief Logika podpisywania dokumentu PDF:
    ## Odczytuje klucz prywatny (PIN), podpisuje hash PDF, zapisuje podpis w metadanych.
    def sign_document(self):
        if not PYPDF_AVAILABLE: messagebox.showerror("Błąd", "Biblioteka pypdf nie jest zainstalowana."); return
        self.set_status(self.sign_status_label, "Rozpoczynanie podpisywania...", "info")
        pdf_path_in = self.pdf_to_sign_path.get(); key_file = self.encrypted_key_path.get(); pin = self.pin_entry_sign.get()
        if not pdf_path_in or not os.path.isfile(pdf_path_in): self.set_status(self.sign_status_label, "BŁĄD: Wybierz PDF.", "error"); return
        if not key_file: self.set_status(self.sign_status_label, "BŁĄD: Brak klucza na nośniku.", "error"); return
        if len(pin) < 4: self.set_status(self.sign_status_label, "BŁĄD: PIN za krótki.", "error"); return
        
        try:
            # KROK 1: Wczytaj i zdeszyfruj klucz prywatny
            self.set_status(self.sign_status_label, "Odczytywanie i deszyfrowanie klucza AES-GCM...", "info")
            with open(key_file, 'rb') as f:
                encrypted_data = f.read()
            
            aes_key = crypto_utils.hash_pin(pin)
            # Rozpakowanie nonce, tagu i ciphertextu
            nonce = encrypted_data[:crypto_utils.AES_NONCE_SIZE]
            tag = encrypted_data[crypto_utils.AES_NONCE_SIZE : crypto_utils.AES_NONCE_SIZE + crypto_utils.AES_TAG_SIZE]
            ciphertext = encrypted_data[crypto_utils.AES_NONCE_SIZE + crypto_utils.AES_TAG_SIZE:]
            
            decrypted_pem = crypto_utils.decrypt_aes_gcm(nonce, tag, ciphertext, aes_key)
            if decrypted_pem is None:
                self.set_status(self.sign_status_label, "BŁĄD: Deszyfrowanie klucza nie powiodło się. Sprawdź PIN.", "error")
                return

            private_key = crypto_utils.load_private_key_from_pem(decrypted_pem, password=None)
            if private_key is None:
                self.set_status(self.sign_status_label, "BŁĄD: Nie udało się załadować klucza z danych PEM.", "error")
                return
            self.set_status(self.sign_status_label, "Klucz prywatny załadowany pomyślnie.", "info")

            # KROK 2: Oblicz hash dokumentu
            self.set_status(self.sign_status_label, "Obliczanie hasha z zawartości PDF...", "info")
            pdf_hash = crypto_utils.hash_pdf_content(pdf_path_in)
            if pdf_hash is None:
                self.set_status(self.sign_status_label, "BŁĄD: Nie udało się obliczyć hasha PDF.", "error"); return

            # KROK 3: Podpisz hash
            self.set_status(self.sign_status_label, "Generowanie podpisu RSA...", "info")
            signature = crypto_utils.sign_rsa(private_key, pdf_hash)
            if signature is None:
                self.set_status(self.sign_status_label, "BŁĄD: Nie udało się wygenerować podpisu.", "error"); return
            
            # KROK 4: Zapisz podpis w nowym pliku PDF
            pdf_path_out_default = os.path.splitext(pdf_path_in)[0] + "_signed.pdf"
            pdf_path_out = filedialog.asksaveasfilename(title="Zapisz podpisany PDF jako...", initialfile=os.path.basename(pdf_path_out_default), initialdir=os.path.dirname(pdf_path_in), 
                                                        defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
            if not pdf_path_out: self.set_status(self.sign_status_label, "Anulowano zapis.", "info"); return

            self.set_status(self.sign_status_label, f"Zapisywanie podpisu w metadanych pliku...", "info")
            reader = PdfReader(pdf_path_in)
            writer = PdfWriter()
            writer.append(reader)
            
            # Dodajemy nasz niestandardowy podpis do metadanych
            writer.add_metadata({"/CustomPAdESSignature": signature.hex()})
            
            with open(pdf_path_out, "wb") as outf:
                writer.write(outf)

            self.set_status(self.sign_status_label, f"SUKCES: Dokument PDF podpisany! Zapisano w: {pdf_path_out}", "success")
            messagebox.showinfo("Podpisano Pomyślnie", f"Plik PDF został podpisany cyfrowo.\nZapisano jako:\n{pdf_path_out}")

        except Exception as e:
             error_msg = f"BŁĄD KRYTYCZNY: {type(e).__name__} - {e}"; self.set_status(self.sign_status_label, error_msg, "error"); self.log_message(f"Szczegóły błędu: {e}", level="ERROR"); messagebox.showerror("Błąd Krytyczny", f"Wystąpił nieoczekiwany błąd:\n{e}")

    ## @brief Logika weryfikacji podpisu PDF:
    ## Porównuje hash dokumentu z podpisem zapisanym w metadanych.
    def verify_signature(self):
        if not PYPDF_AVAILABLE: messagebox.showerror("Błąd", "Biblioteka pypdf nie jest zainstalowana."); return
        self.set_status(self.verify_status_label, "Rozpoczynanie weryfikacji...", "info")
        pdf_path = self.pdf_to_verify_path.get(); pubkey_pem_path = self.public_key_path_verify.get()
        if not pdf_path or not os.path.isfile(pdf_path): self.set_status(self.verify_status_label, "BŁĄD: Wybierz poprawny, podpisany plik PDF.", "error"); return
        if not pubkey_pem_path or not os.path.isfile(pubkey_pem_path): self.set_status(self.verify_status_label, "BŁĄD: Wybierz plik klucza publicznego (.pem).", "error"); return

        try:
            # KROK 1: Otwórz PDF i odczytaj podpis z metadanych
            self.log_message(f"Odczytywanie pliku: {os.path.basename(pdf_path)}")
            reader = PdfReader(pdf_path)
            signature_hex = reader.metadata.get("/CustomPAdESSignature")

            if not signature_hex:
                self.set_status(self.verify_status_label, "BŁĄD: W pliku nie znaleziono niestandardowego podpisu.", "error")
                messagebox.showerror("Brak Podpisu", "W metadanych tego pliku PDF nie znaleziono pola '/CustomPAdESSignature'.")
                return
            
            signature_bytes = bytes.fromhex(str(signature_hex)) # Upewniamy się, że to string
            self.log_message("Podpis znaleziony w metadanych, odczytano.")

            # KROK 2: Oblicz aktualny hash zawartości PDF
            self.log_message("Obliczanie hasha z zawartości dokumentu...")
            current_hash = crypto_utils.hash_pdf_content(pdf_path)
            if current_hash is None:
                self.set_status(self.verify_status_label, "BŁĄD: Nie udało się obliczyć hasha PDF.", "error"); return
            self.log_message(f"Obliczony hash: {current_hash.hex()}")

            # KROK 3: Wczytaj klucz publiczny
            self.log_message(f"Wczytywanie klucza publicznego z: {os.path.basename(pubkey_pem_path)}")
            with open(pubkey_pem_path, 'rb') as f:
                public_key = crypto_utils.load_public_key_from_pem(f.read())
            if public_key is None:
                self.set_status(self.verify_status_label, "BŁĄD: Nie udało się załadować klucza publicznego.", "error"); return
            
            # KROK 4: Zweryfikuj podpis
            self.log_message("Weryfikacja kryptograficzna podpisu...")
            is_valid = crypto_utils.verify_rsa(public_key, signature_bytes, current_hash)
            
            if is_valid:
                final_message = "Podpis jest POPRAWNY.\nDokument nie został zmieniony od czasu podpisania."
                self.set_status(self.verify_status_label, "Weryfikacja zakończona: PODPIS POPRAWNY.", "success")
                messagebox.showinfo("Weryfikacja Pomyślna", final_message)
            else:
                final_message = "Podpis jest NIEPOPRAWNY!\nDokument mógł zostać zmieniony lub użyto złego klucza."
                self.set_status(self.verify_status_label, "Weryfikacja zakończona: PODPIS NIEPOPRAWNY.", "error")
                messagebox.showerror("Weryfikacja Niepomyślna", final_message)

        except Exception as e:
            error_msg = f"BŁĄD KRYTYCZNY weryfikacji: {type(e).__name__} - {e}"; self.set_status(self.verify_status_label, error_msg, "error"); self.log_message(f"Szczegóły błędu: {e}", level="ERROR"); messagebox.showerror("Błąd Krytyczny", f"Wystąpił nieoczekiwany błąd:\n{e}")

if __name__ == "__main__":
    if not PYPDF_AVAILABLE: print("\nProszę zainstalować pypdf ('pip install pypdf') i uruchomić aplikację ponownie.")
    app = SignVerifyApp()
    app.mainloop()