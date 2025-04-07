import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import crypto_utils
import drive_utils

class GenerateKeysApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Generator Kluczy BSK/SCS")
        self.geometry("500x450")

        # Style
        style = ttk.Style(self)
        style.configure('TButton', padding=6)
        style.configure('TLabel', padding=2)
        style.configure('TEntry', padding=4)

        # --- Elementy GUI ---
        # PIN
        ttk.Label(self, text="Wprowadź PIN (min. 4 znaki):").pack(pady=(10,0))
        self.pin_entry = ttk.Entry(self, show="*", width=30)
        self.pin_entry.pack()

        # Wybór Pendrive'a
        ttk.Label(self, text="Wybierz Pendrive docelowy:").pack(pady=(10,0))
        self.drive_combobox = ttk.Combobox(self, state="readonly", width=40)
        self.drive_combobox.pack()
        self.refresh_drives_button = ttk.Button(self, text="Odśwież listę dysków", command=self.refresh_drive_list)
        self.refresh_drives_button.pack(pady=5)

        # Przycisk Generowania
        self.generate_button = ttk.Button(self, text="Generuj Klucze i Zapisz", command=self.generate_and_save_keys)
        self.generate_button.pack(pady=20)

        # Status/Logi
        ttk.Label(self, text="Status operacji:").pack()
        self.status_text = scrolledtext.ScrolledText(self, height=10, width=60, wrap=tk.WORD, state=tk.DISABLED)
        self.status_text.pack(padx=10, pady=5, expand=True, fill=tk.BOTH)

        # Inicjalizacja
        self.refresh_drive_list()

    def log_status(self, message):
        """Dodaje wiadomość do pola statusu."""
        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.see(tk.END)
        self.status_text.config(state=tk.DISABLED)
        self.update_idletasks() 

    def refresh_drive_list(self):
        """Odświeża listę dostępnych dysków wymiennych."""
        self.log_status("Odświeżanie listy dysków wymiennych...")
        drives = drive_utils.list_removable_drives()
        if drives:
            self.drive_combobox['values'] = drives
            self.drive_combobox.current(0)
            self.log_status(f"Znaleziono dyski: {', '.join(drives)}")
        else:
            self.drive_combobox['values'] = []
            self.drive_combobox.set('')
            self.log_status("Nie znaleziono żadnych dysków wymiennych.")


    def generate_and_save_keys(self):
        """Główna funkcja wywoływana po kliknięciu przycisku."""
        pin = self.pin_entry.get()
        selected_drive = self.drive_combobox.get()

        # Walidacja danych wejściowych
        if len(pin) < 4:
            messagebox.showerror("Błąd", "PIN musi mieć co najmniej 4 znaki.")
            return
        if not selected_drive:
            messagebox.showerror("Błąd", "Wybierz pendrive docelowy z listy.")
            return
        if not os.path.isdir(selected_drive):
             messagebox.showerror("Błąd", f"Wybrana ścieżka '{selected_drive}' nie jest dostępnym katalogiem. Odśwież listę.")
             return

        # Generowanie
        try:
            self.log_status("Rozpoczynanie generowania kluczy RSA (4096 bit)... Może to chwilę potrwać.")
            private_key, public_key = crypto_utils.generate_rsa_keys()
            self.log_status("Klucze RSA wygenerowane pomyślnie.")

            # Serializacja kluczy
            private_pem = crypto_utils.serialize_private_key(private_key)
            public_pem = crypto_utils.serialize_public_key(public_key)
            self.log_status("Klucze zserializowane do formatu PEM.")

            # Szyfrowanie klucza prywatnego
            self.log_status("Haszowanie PINu (SHA-256)...")
            aes_key = crypto_utils.hash_pin(pin)
            self.log_status(f"Klucz AES (hash PINu): {aes_key.hex()}") # debug

            self.log_status("Szyfrowanie klucza prywatnego (AES-GCM)...")
            nonce, tag, encrypted_private_pem_only = crypto_utils.encrypt_aes_gcm(private_pem, aes_key)
            self.log_status("Klucz prywatny zaszyfrowany.")


            public_key_path = filedialog.asksaveasfilename(
                title="Zapisz klucz publiczny jako...",
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            # Sprawdzenie, czy użytkownik wybrał plik (nie anulował)
            if not public_key_path:
                self.log_status("Anulowano zapis klucza publicznego.")
                return # Użytkownik anulował, przerwij funkcję

            # Zapisanie pliku klucza publicznego
            with open(public_key_path, 'wb') as f_pub:
                f_pub.write(public_pem)
            self.log_status(f"Klucz publiczny zapisany w: {public_key_path}")

            # Zapis zaszyfrowanego klucza prywatnego na pendrive
            private_key_file_path = os.path.join(selected_drive, drive_utils.KEY_FILENAME)
            self.log_status(f"Zapisywanie zaszyfrowanego klucza pryw. na: {private_key_file_path}")

            # Zaktualizowany format pliku: [NONCE (12 bajtów)][TAG (16 bajtów)][ZASZYFROWANE DANE PEM]
            with open(private_key_file_path, 'wb') as f_priv:
                f_priv.write(nonce) # 12 bajtów
                f_priv.write(tag)   # 16 bajtów (standardowy rozmiar tagu GCM)
                f_priv.write(encrypted_private_pem_only) # Reszta danych

            self.log_status("Operacja zakończona pomyślnie!")
            # Teraz zmienna 'public_key_path' już istnieje i można jej bezpiecznie użyć
            messagebox.showinfo("Sukces", f"Klucze wygenerowane.\nKlucz publiczny zapisany w: {public_key_path}\nZaszyfrowany klucz prywatny zapisany na pendrive: {private_key_file_path}")

        except Exception as e:
            self.log_status(f"WYSTĄPIŁ BŁĄD: {e}")
            messagebox.showerror("Błąd Krytyczny", f"Wystąpił nieoczekiwany błąd:\n{e}")


if __name__ == "__main__":
    app = GenerateKeysApp()
    app.mainloop()