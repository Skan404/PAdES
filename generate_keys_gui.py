import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
try:
    import crypto_utils
    import drive_utils
except ImportError as e:
    messagebox.showerror("Błąd importu", f"Nie można zaimportować modułów lub brak wymaganych funkcji: {e}\n")
    exit()
import traceback

class GenerateKeysApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Generator Kluczy BSK") 
        self.geometry("550x500")

        # Style
        style = ttk.Style(self)
        style.configure('TButton', padding=6, font=('Helvetica', 10))
        style.configure('TLabel', padding=2, font=('Helvetica', 10))
        style.configure('TEntry', padding=4, font=('Helvetica', 10))
        style.configure('TCombobox', padding=4, font=('Helvetica', 10))

        # Ramka główna
        main_frame = ttk.Frame(self, padding="10 10 10 10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        # --- Elementy GUI ---
        # PIN
        pin_label = ttk.Label(main_frame, text="Wprowadź PIN (min. 4 znaki):")
        pin_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.pin_entry = ttk.Entry(main_frame, show="*", width=35)
        self.pin_entry.grid(row=1, column=0, sticky=tk.EW, pady=(0, 10))

        # Wybór Pendrive'a
        drive_label = ttk.Label(main_frame, text="Wybierz Pendrive docelowy:")
        drive_label.grid(row=2, column=0, sticky=tk.W, pady=(0, 5))

        drive_frame = ttk.Frame(main_frame)
        drive_frame.grid(row=3, column=0, sticky=tk.EW, pady=(0, 10))

        self.drive_combobox = ttk.Combobox(drive_frame, state="readonly", width=40)
        self.drive_combobox.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

        self.refresh_drives_button = ttk.Button(drive_frame, text="Odśwież", command=self.refresh_drive_list)
        self.refresh_drives_button.pack(side=tk.LEFT)

        # Przycisk Generowania
        self.generate_button = ttk.Button(main_frame, text="Generuj Klucze i Zapisz (Format PEM)", command=self.generate_and_save_keys) # Zmieniono tekst przycisku
        self.generate_button.grid(row=4, column=0, pady=20)

        # Status/Logi
        log_label = ttk.Label(main_frame, text="Status operacji:")
        log_label.grid(row=5, column=0, sticky=tk.W, pady=(10, 5))
        self.status_text = scrolledtext.ScrolledText(main_frame, height=10, width=60, wrap=tk.WORD, state=tk.DISABLED, font=('Courier New', 9))
        self.status_text.grid(row=6, column=0, sticky=tk.NSEW)

        # Konfiguracja rozciągania
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(6, weight=1)

        # Inicjalizacja
        self.refresh_drive_list()

    def log_status(self, message):
        """Dodaje wiadomość do pola statusu."""
        try:
            self.status_text.config(state=tk.NORMAL)
            self.status_text.insert(tk.END, message + "\n")
            self.status_text.see(tk.END)
            self.status_text.config(state=tk.DISABLED)
            self.update_idletasks()
        except Exception as e:
            print(f"Błąd logowania: {e}")

    def refresh_drive_list(self):
        """Odświeża listę dostępnych dysków wymiennych."""
        self.log_status("Odświeżanie listy dysków wymiennych...")
        try:
            drives = drive_utils.list_removable_drives()
            if drives:
                self.drive_combobox['values'] = drives
                self.drive_combobox.current(0)
                self.log_status(f"Znaleziono dyski: {', '.join(drives)}")
            else:
                self.drive_combobox['values'] = []
                self.drive_combobox.set('')
                self.log_status("Nie znaleziono żadnych dysków wymiennych.")
        except Exception as e:
            self.log_status(f"BŁĄD podczas odświeżania listy dysków: {e}")
            messagebox.showerror("Błąd odświeżania", f"Wystąpił błąd podczas wyszukiwania dysków:\n{e}")


    def generate_and_save_keys(self):
        """Generuje klucze, szyfruje AES-GCM, OPAKOWUJE w pseudo-PEM i zapisuje."""
        pin = self.pin_entry.get()
        selected_drive = self.drive_combobox.get()

        # Walidacja danych wejsciowych
        if len(pin) < 4:
            messagebox.showerror("Błąd Walidacji", "PIN musi mieć co najmniej 4 znaki.")
            self.log_status("BŁĄD: PIN za krótki.")
            return
        if not selected_drive:
            messagebox.showerror("Błąd Walidacji", "Wybierz pendrive docelowy z listy.")
            self.log_status("BŁĄD: Nie wybrano pendrive'a.")
            return
        if not os.path.isdir(selected_drive):
            messagebox.showerror("Błąd Walidacji", f"Wybrana ścieżka '{selected_drive}' nie jest dostępnym katalogiem.\nOdśwież listę dysków.")
            self.log_status(f"BŁĄD: Wybrana ścieżka '{selected_drive}' jest niedostępna.")
            return

        # logika generowania i zapisu
        try:
            self.log_status(">>> Rozpoczynanie procesu generowania i zapisu kluczy (Format PEM) <<<")
            self.generate_button.config(state=tk.DISABLED)
            self.update_idletasks()

            self.log_status("1. Generowanie pary kluczy RSA (4096 bit)...")
            private_key, public_key = crypto_utils.generate_rsa_keys()
            self.log_status("   Klucze RSA wygenerowane.")

            # serializacjia i zapis klucza publicznego
            self.log_status("2. Serializacja i zapis klucza publicznego...")
            public_pem = crypto_utils.serialize_public_key(public_key)
            public_key_path = filedialog.asksaveasfilename(
                title="Zapisz klucz publiczny jako...",
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not public_key_path:
                self.log_status("Anulowano zapis klucza publicznego. Przerwano.")
                self.generate_button.config(state=tk.NORMAL)
                return
            try:
                with open(public_key_path, 'wb') as f_pub:
                    f_pub.write(public_pem)
                self.log_status(f"   Klucz publiczny zapisany w: {public_key_path}")
            except Exception as e:
                self.log_status(f"BŁĄD zapisu klucza publicznego: {e}")
                messagebox.showerror("Błąd Zapisu", f"Nie można zapisać klucza publicznego w:\n{public_key_path}\nBłąd: {e}")
                self.generate_button.config(state=tk.NORMAL)
                return

            # szyfrowanie i zapis klucza prywatnego
            self.log_status("3. Serializacja klucza prywatnego (w pamięci)...")
            private_pem_unencrypted = crypto_utils.serialize_private_key(private_key)
            self.log_status("   Klucz prywatny zserializowany.")

            self.log_status("4. Haszowanie PINu (SHA-256) dla klucza AES...")
            aes_key = crypto_utils.hash_pin(pin)
            self.log_status("   Klucz AES wygenerowany.")

            self.log_status("5. Szyfrowanie klucza prywatnego (AES-GCM)...")
            nonce, tag, encrypted_private_pem_data = crypto_utils.encrypt_aes_gcm(
                private_pem_unencrypted, aes_key
            )
            self.log_status("   Klucz prywatny zaszyfrowany (AES-GCM).")

            # zaszyfrowane dane binarne w jeden blob
            binary_blob = nonce + tag + encrypted_private_pem_data

            # dane binarne w strukturę tekstową PEM
            self.log_status("6. Opakowywanie zaszyfrowanych danych w format tekstowy PEM...")
            pem_output_string = crypto_utils.wrap_binary_data_in_pem(binary_blob)
            self.log_status("   Dane opakowane (Base64 + nagłówki).")

            private_key_file_path = os.path.join(selected_drive, drive_utils.KEY_FILENAME)
            self.log_status(f"7. Zapisywanie klucza prywatnego (Format PEM) na pendrive:")
            self.log_status(f"   Ścieżka: {private_key_file_path}")

            # zapisujemy jako tekst w ascii
            try:
                with open(private_key_file_path, 'w', encoding='ascii') as f_priv:
                    f_priv.write(pem_output_string)
                self.log_status(f"   Zaszyfrowany klucz prywatny (format PEM) zapisany pomyślnie.")
            except Exception as e:
                self.log_status(f"BŁĄD podczas zapisu klucza prywatnego (format PEM) na pendrive: {e}")
                messagebox.showerror("Błąd Zapisu", f"Nie można zapisać zaszyfrowanego klucza prywatnego (format PEM) na:\n{private_key_file_path}\nBłąd: {e}")
                try:
                    os.remove(public_key_path)
                    self.log_status(f"   Usunięto zapisany wcześniej klucz publiczny z powodu błędu.")
                except OSError as rm_err:
                    self.log_status(f"   Nie udało się usunąć pliku klucza publicznego po błędzie: {rm_err}")
                self.generate_button.config(state=tk.NORMAL)
                return

            self.log_status(">>> Operacja zakończona pomyślnie! <<<")
            messagebox.showinfo("Sukces", f"Klucze wygenerowane i zapisane pomyślnie.\n\nKlucz publiczny:\n{public_key_path}\n\nZaszyfrowany klucz prywatny (format PEM):\n{private_key_file_path}")

        except crypto_utils.ValueError as ve:
            self.log_status(f"BŁĄD WARTOŚCI (crypto_utils): {ve}")
            messagebox.showerror("Błąd Danych", f"Wystąpił błąd związany z danymi kryptograficznymi:\n{ve}")
        except Exception as e:
            self.log_status(f"BŁĄD KRYTYCZNY: {e}")
            self.log_status(traceback.format_exc())
            messagebox.showerror("Błąd Krytyczny", f"Wystąpił nieoczekiwany błąd:\n{e}\n\nSprawdź logi aplikacji po szczegóły.")
        finally:
            self.generate_button.config(state=tk.NORMAL)

if __name__ == "__main__":
    try:
        app = GenerateKeysApp()
        app.mainloop()
    except Exception as start_error:
        print(f"Błąd krytyczny podczas uruchamiania aplikacji: {start_error}")
        messagebox.showerror("Błąd Uruchomienia", f"Nie można uruchomić aplikacji:\n{start_error}")