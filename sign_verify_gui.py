import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import time
import crypto_utils
import drive_utils

class SignVerifyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Podpisywanie i Weryfikacja Plików PDF - BSK")
        self.geometry("650x550") # Trochę większe okno

        # Style
        style = ttk.Style(self)
        style.configure('TButton', padding=6)
        style.configure('TLabel', padding=2)
        style.configure('TEntry', padding=4)
        style.configure('Status.TLabel', font=('Helvetica', 10, 'italic'))
        style.configure('Success.Status.TLabel', foreground='green')
        style.configure('Error.Status.TLabel', foreground='red')
        style.configure('Info.Status.TLabel', foreground='blue')

        # Zmienne stanu
        self.pdf_to_sign_path = tk.StringVar()
        self.pdf_to_verify_path = tk.StringVar()
        self.public_key_path = tk.StringVar()
        self.signature_file_path = tk.StringVar() # Ścieżka do pliku .sig
        self.encrypted_key_path = tk.StringVar() # Ścieżka do znalezionego private_key.enc

        # --- Główne zakładki ---
        self.notebook = ttk.Notebook(self)

        self.sign_frame = ttk.Frame(self.notebook, padding="10")
        self.verify_frame = ttk.Frame(self.notebook, padding="10")

        self.notebook.add(self.sign_frame, text='Podpisywanie Dokumentu PDF')
        self.notebook.add(self.verify_frame, text='Weryfikacja Podpisu PDF')
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # --- Zakładka Podpisywania ---
        self._create_sign_widgets()

        # --- Zakładka Weryfikacji ---
        self._create_verify_widgets()

        # --- Logi Aplikacji ---
        ttk.Label(self, text="Logi aplikacji:").pack(pady=(5,0))
        self.log_text = scrolledtext.ScrolledText(self, height=8, width=80, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(padx=10, pady=5, expand=True, fill=tk.BOTH)

        # --- Automatyczne wykrywanie pendrive'a ---
        self.check_pendrive() # Sprawdź od razu
        # Ustaw cykliczne sprawdzanie co 5 sekund (5000 ms)
        self.after(5000, self.check_pendrive_periodically)


    def log_message(self, message, level="INFO"):
        """Dodaje wiadomość do logów."""
        self.log_text.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp} {level}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.update_idletasks()

    def _create_sign_widgets(self):
        frame = self.sign_frame

        # Wybór PDF do podpisania
        row = 0
        ttk.Label(frame, text="1. Wybierz plik PDF do podpisania:").grid(row=row, column=0, sticky=tk.W, pady=2)
        row += 1
        pdf_sign_entry = ttk.Entry(frame, textvariable=self.pdf_to_sign_path, width=60, state='readonly')
        pdf_sign_entry.grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=(0, 5))
        pdf_sign_button = ttk.Button(frame, text="Przeglądaj...", command=self.select_pdf_to_sign)
        pdf_sign_button.grid(row=row, column=2, sticky=tk.W)

        # Status Pendrive'a
        row += 1
        ttk.Label(frame, text="2. Status klucza prywatnego na Pendrive:").grid(row=row, column=0, sticky=tk.W, pady=(10, 2))
        row += 1
        self.pendrive_status_label = ttk.Label(frame, text="Oczekiwanie...", style='Info.Status.TLabel', width=60)
        self.pendrive_status_label.grid(row=row, column=0, columnspan=3, sticky=tk.W)

        # Wprowadzenie PINu
        row += 1
        ttk.Label(frame, text="3. Wprowadź PIN do klucza prywatnego:").grid(row=row, column=0, sticky=tk.W, pady=(10, 2))
        row += 1
        self.pin_entry_sign = ttk.Entry(frame, show="*", width=30)
        self.pin_entry_sign.grid(row=row, column=0, columnspan=3, sticky=tk.W)

        # Przycisk Podpisania
        row += 1
        sign_button = ttk.Button(frame, text="Podpisz Dokument", command=self.sign_document)
        sign_button.grid(row=row, column=0, columnspan=3, pady=20)

        # Status Operacji Podpisywania
        row += 1
        ttk.Label(frame, text="Status operacji:").grid(row=row, column=0, sticky=tk.W, pady=(10, 2))
        row += 1
        self.sign_status_label = ttk.Label(frame, text="-", style='Status.TLabel', width=60)
        self.sign_status_label.grid(row=row, column=0, columnspan=3, sticky=tk.W)


    def _create_verify_widgets(self):
        frame = self.verify_frame

        # Wybór PDF do weryfikacji
        row = 0
        ttk.Label(frame, text="1. Wybierz podpisany plik PDF:").grid(row=row, column=0, sticky=tk.W, pady=2)
        row += 1
        pdf_verify_entry = ttk.Entry(frame, textvariable=self.pdf_to_verify_path, width=60, state='readonly')
        pdf_verify_entry.grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=(0, 5))
        pdf_verify_button = ttk.Button(frame, text="Przeglądaj...", command=self.select_pdf_to_verify)
        pdf_verify_button.grid(row=row, column=2, sticky=tk.W)

        # Wybór Klucza Publicznego
        row += 1
        ttk.Label(frame, text="2. Wybierz plik klucza publicznego (.pem):").grid(row=row, column=0, sticky=tk.W, pady=(10, 2))
        row += 1
        pubkey_entry = ttk.Entry(frame, textvariable=self.public_key_path, width=60, state='readonly')
        pubkey_entry.grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=(0, 5))
        pubkey_button = ttk.Button(frame, text="Przeglądaj...", command=self.select_public_key)
        pubkey_button.grid(row=row, column=2, sticky=tk.W)

        # Wybór Pliku Podpisu (.sig)
        row += 1
        ttk.Label(frame, text="3. Wybierz plik podpisu (.sig):").grid(row=row, column=0, sticky=tk.W, pady=(10, 2))
        row += 1
        sig_entry = ttk.Entry(frame, textvariable=self.signature_file_path, width=60, state='readonly')
        sig_entry.grid(row=row, column=0, columnspan=2, sticky=tk.EW, padx=(0, 5))
        sig_button = ttk.Button(frame, text="Przeglądaj...", command=self.select_signature_file)
        sig_button.grid(row=row, column=2, sticky=tk.W)

        # Przycisk Weryfikacji
        row += 1
        verify_button = ttk.Button(frame, text="Weryfikuj Podpis", command=self.verify_signature)
        verify_button.grid(row=row, column=0, columnspan=3, pady=20)

         # Status Operacji Weryfikacji
        row += 1
        ttk.Label(frame, text="Status operacji:").grid(row=row, column=0, sticky=tk.W, pady=(10, 2))
        row += 1
        self.verify_status_label = ttk.Label(frame, text="-", style='Status.TLabel', width=60)
        self.verify_status_label.grid(row=row, column=0, columnspan=3, sticky=tk.W)

    def set_status(self, label_widget, message, level="info"):
        """Ustawia tekst i styl etykiety statusu."""
        label_widget.config(text=message)
        if level == "success":
            label_widget.config(style='Success.Status.TLabel')
        elif level == "error":
            label_widget.config(style='Error.Status.TLabel')
        else:
            label_widget.config(style='Info.Status.TLabel')
        self.log_message(message, level.upper())

    def check_pendrive(self):
        """Sprawdza obecność klucza na pendrive i aktualizuje status."""
        key_path = drive_utils.find_key_on_removable_drives()
        if key_path:
            self.encrypted_key_path.set(key_path)
            self.set_status(self.pendrive_status_label, f"OK: Znaleziono klucz: {key_path}", "success")
            return True
        else:
            self.encrypted_key_path.set("")
            self.set_status(self.pendrive_status_label, "BŁĄD: Nie znaleziono pliku 'private_key.enc' na żadnym pendrive.", "error")
            return False

    def check_pendrive_periodically(self):
        """Funkcja do cyklicznego sprawdzania pendrive."""
        self.check_pendrive()
        self.after(5000, self.check_pendrive_periodically) # Zaplanuj kolejne sprawdzenie

    def select_pdf_to_sign(self):
        path = filedialog.askopenfilename(
            title="Wybierz plik PDF do podpisania",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if path:
            self.pdf_to_sign_path.set(path)
            self.log_message(f"Wybrano plik do podpisania: {path}")

    def select_pdf_to_verify(self):
        path = filedialog.askopenfilename(
            title="Wybierz podpisany plik PDF",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if path:
            self.pdf_to_verify_path.set(path)
            self.log_message(f"Wybrano plik PDF do weryfikacji: {path}")

    def select_public_key(self):
        path = filedialog.askopenfilename(
            title="Wybierz klucz publiczny",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if path:
            self.public_key_path.set(path)
            self.log_message(f"Wybrano klucz publiczny: {path}")

    def select_signature_file(self):
        path = filedialog.askopenfilename(
            title="Wybierz plik podpisu",
            filetypes=[("Signature files", "*.sig"), ("All files", "*.*")]
        )
        if path:
            self.signature_file_path.set(path)
            self.log_message(f"Wybrano plik podpisu: {path}")

    def sign_document(self):
        """Logika podpisywania dokumentu."""
        self.set_status(self.sign_status_label, "Rozpoczynanie podpisywania...", "info")

        # Walidacja
        pdf_path = self.pdf_to_sign_path.get()
        key_file = self.encrypted_key_path.get()
        pin = self.pin_entry_sign.get()

        if not pdf_path or not os.path.isfile(pdf_path):
            self.set_status(self.sign_status_label, "BŁĄD: Wybierz poprawny plik PDF.", "error")
            messagebox.showerror("Błąd", "Nie wybrano pliku PDF do podpisania.")
            return
        if not key_file:
             self.set_status(self.sign_status_label, "BŁĄD: Nie znaleziono klucza na pendrive.", "error")
             messagebox.showerror("Błąd", "Nie wykryto pliku klucza 'private_key.enc' na podłączonych pendrive'ach.")
             return
        if len(pin) < 4:
             self.set_status(self.sign_status_label, "BŁĄD: PIN jest za krótki.", "error")
             messagebox.showerror("Błąd", "PIN musi mieć co najmniej 4 znaki.")
             return

        # Główna logika
        try:
            self.set_status(self.sign_status_label, "Odczytywanie zaszyfrowanego klucza...", "info")
            # Odczytaj plik zgodnie z nowym formatem: [NONCE][TAG][CIPHERTEXT]
            with open(key_file, 'rb') as f:
                nonce = f.read(crypto_utils.AES_NONCE_SIZE)     # 12 bajtów
                tag = f.read(crypto_utils.AES_TAG_SIZE)         # 16 bajtów
                encrypted_pem_only = f.read()                   # Reszta

            # Sprawdź czy odczytano wystarczającą ilość danych
            if len(nonce) != crypto_utils.AES_NONCE_SIZE or len(tag) != crypto_utils.AES_TAG_SIZE:
                 self.set_status(self.sign_status_label, "BŁĄD: Plik klucza jest uszkodzony lub ma nieprawidłowy format.", "error")
                 messagebox.showerror("Błąd Pliku Klucza", f"Plik '{key_file}' wydaje się uszkodzony lub nie został wygenerowany przez tę wersję programu.")
                 return

            self.set_status(self.sign_status_label, "Haszowanie PINu i deszyfrowanie klucza...", "info")
            aes_key = crypto_utils.hash_pin(pin)
            # Przekaż tag jako oddzielny argument do funkcji deszyfrującej
            decrypted_pem = crypto_utils.decrypt_aes_gcm(nonce, tag, encrypted_pem_only, aes_key)

            if decrypted_pem is None:
                # Błąd deszyfrowania (np. zły PIN) został już zalogowany w crypto_utils
                self.set_status(self.sign_status_label, "BŁĄD: Deszyfrowanie klucza nie powiodło się (zły PIN?).", "error")
                messagebox.showerror("Błąd Deszyfrowania", "Nie można odszyfrować klucza prywatnego. Sprawdź PIN lub czy plik klucza nie jest uszkodzony.")
                return

            self.set_status(self.sign_status_label, "Ładowanie klucza prywatnego...", "info")
            private_key = crypto_utils.load_private_key_from_pem(decrypted_pem)
            if private_key is None:
                 self.set_status(self.sign_status_label, "BŁĄD: Nie można załadować klucza prywatnego.", "error")
                 messagebox.showerror("Błąd Klucza", "Format odszyfrowanego klucza prywatnego jest nieprawidłowy.")
                 return


            self.set_status(self.sign_status_label, f"Haszowanie pliku PDF ({os.path.basename(pdf_path)})...", "info")
            pdf_hash = crypto_utils.hash_file(pdf_path)
            if pdf_hash is None:
                self.set_status(self.sign_status_label, "BŁĄD: Nie można obliczyć hasha PDF.", "error")
                messagebox.showerror("Błąd Hashowania", f"Nie udało się obliczyć skrótu dla pliku {pdf_path}.")
                return
            self.log_message(f"Hash PDF: {pdf_hash.hex()}")

            self.set_status(self.sign_status_label, "Generowanie podpisu RSA...", "info")
            signature = crypto_utils.sign_rsa(private_key, pdf_hash)
            if signature is None:
                self.set_status(self.sign_status_label, "BŁĄD: Generowanie podpisu RSA nie powiodło się.", "error")
                messagebox.showerror("Błąd Podpisywania", "Wystąpił błąd podczas generowania podpisu RSA.")
                return
            self.log_message(f"Wygenerowany podpis (fragment): {signature[:16].hex()}...") # Pokaż tylko początek

            # Zapis podpisu do pliku .sig
            sig_path_default = pdf_path + ".sig"
            sig_path = filedialog.asksaveasfilename(
                title="Zapisz plik podpisu jako...",
                initialfile=os.path.basename(sig_path_default),
                initialdir=os.path.dirname(pdf_path),
                defaultextension=".sig",
                filetypes=[("Signature files", "*.sig"), ("All files", "*.*")]
            )

            if not sig_path:
                self.set_status(self.sign_status_label, "Anulowano zapis podpisu.", "info")
                return

            with open(sig_path, 'wb') as f_sig:
                f_sig.write(signature)

            self.set_status(self.sign_status_label, f"SUKCES: Dokument podpisany! Podpis zapisano w: {sig_path}", "success")
            messagebox.showinfo("Podpisano Pomyślnie", f"Plik PDF został podpisany.\nPodpis zapisano w:\n{sig_path}")

        except FileNotFoundError as e:
             self.set_status(self.sign_status_label, f"BŁĄD Pliku: {e}", "error")
             messagebox.showerror("Błąd Pliku", f"Nie znaleziono pliku: {e}")
        except Exception as e:
            self.set_status(self.sign_status_label, f"BŁĄD KRYTYCZNY: {e}", "error")
            self.log_message(f"Szczegóły błędu: {type(e).__name__}: {e}", level="ERROR")
            messagebox.showerror("Błąd Krytyczny", f"Wystąpił nieoczekiwany błąd podczas podpisywania:\n{e}")

    def verify_signature(self):
        """Logika weryfikacji podpisu."""
        self.set_status(self.verify_status_label, "Rozpoczynanie weryfikacji...", "info")

        # Walidacja
        pdf_path = self.pdf_to_verify_path.get()
        pubkey_path = self.public_key_path.get()
        sig_path = self.signature_file_path.get()

        if not pdf_path or not os.path.isfile(pdf_path):
             self.set_status(self.verify_status_label, "BŁĄD: Wybierz poprawny plik PDF.", "error")
             messagebox.showerror("Błąd", "Nie wybrano pliku PDF do weryfikacji.")
             return
        if not pubkey_path or not os.path.isfile(pubkey_path):
            self.set_status(self.verify_status_label, "BŁĄD: Wybierz poprawny plik klucza publicznego.", "error")
            messagebox.showerror("Błąd", "Nie wybrano pliku klucza publicznego (.pem).")
            return
        if not sig_path or not os.path.isfile(sig_path):
             self.set_status(self.verify_status_label, "BŁĄD: Wybierz poprawny plik podpisu.", "error")
             messagebox.showerror("Błąd", "Nie wybrano pliku podpisu (.sig).")
             return

        # Główna logika
        try:
            self.set_status(self.verify_status_label, "Wczytywanie klucza publicznego...", "info")
            with open(pubkey_path, 'rb') as f:
                pubkey_pem = f.read()
            public_key = crypto_utils.load_public_key_from_pem(pubkey_pem)
            if public_key is None:
                self.set_status(self.verify_status_label, "BŁĄD: Nie można załadować klucza publicznego.", "error")
                messagebox.showerror("Błąd Klucza", "Format pliku klucza publicznego jest nieprawidłowy.")
                return

            self.set_status(self.verify_status_label, "Wczytywanie pliku podpisu...", "info")
            with open(sig_path, 'rb') as f:
                signature = f.read()
            self.log_message(f"Odczytany podpis (fragment): {signature[:16].hex()}...")

            self.set_status(self.verify_status_label, f"Haszowanie pliku PDF ({os.path.basename(pdf_path)})...", "info")
            pdf_hash = crypto_utils.hash_file(pdf_path)
            if pdf_hash is None:
                self.set_status(self.verify_status_label, "BŁĄD: Nie można obliczyć hasha PDF.", "error")
                messagebox.showerror("Błąd Hashowania", f"Nie udało się obliczyć skrótu dla pliku {pdf_path}.")
                return
            self.log_message(f"Obliczony hash PDF: {pdf_hash.hex()}")

            self.set_status(self.verify_status_label, "Weryfikowanie podpisu RSA...", "info")
            is_valid = crypto_utils.verify_rsa(public_key, signature, pdf_hash)

            if is_valid:
                self.set_status(self.verify_status_label, "SUKCES: Podpis jest POPRAWNY.", "success")
                messagebox.showinfo("Weryfikacja Zakończona", "Podpis pliku PDF jest poprawny.")
            else:
                # Komunikat błędu jest już logowany w crypto_utils.verify_rsa
                self.set_status(self.verify_status_label, "BŁĄD: Podpis jest NIEPOPRAWNY (lub plik został zmieniony).", "error")
                messagebox.showwarning("Weryfikacja Zakończona", "Podpis pliku PDF jest NIEPOPRAWNY.\nMożliwe przyczyny:\n- Dokument PDF został zmodyfikowany po podpisaniu.\n- Użyto niewłaściwego klucza publicznego do weryfikacji.\n- Plik podpisu jest uszkodzony lub nie odpowiada temu dokumentowi.")

        except FileNotFoundError as e:
             self.set_status(self.verify_status_label, f"BŁĄD Pliku: {e}", "error")
             messagebox.showerror("Błąd Pliku", f"Nie znaleziono pliku: {e}")
        except Exception as e:
            self.set_status(self.verify_status_label, f"BŁĄD KRYTYCZNY: {e}", "error")
            self.log_message(f"Szczegóły błędu: {type(e).__name__}: {e}", level="ERROR")
            messagebox.showerror("Błąd Krytyczny", f"Wystąpił nieoczekiwany błąd podczas weryfikacji:\n{e}")


if __name__ == "__main__":
    app = SignVerifyApp()
    app.mainloop()