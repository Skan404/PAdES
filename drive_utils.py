import os
import psutil
import sys

# Nazwa pliku klucza na pendrive
KEY_FILENAME = "private_key.pem"

def list_removable_drives():
    """Zwraca listę ścieżek montowania dysków wymiennych (potencjalnych pendrive'ów)."""
    removable_drives = []
    partitions = psutil.disk_partitions(all=False) # all=False pomija wirtualne spacje
    for p in partitions:
        if 'removable' in p.opts.lower():
             # czy sciezka istnieje i jest katalogiem
            if os.path.isdir(p.mountpoint):
                removable_drives.append(p.mountpoint)
                continue # przejdz do kolejnej partycji

        # Sprawdzamy typ systemu plików - FAT/exFAT
        # lub po prostu sprawdzamy czy litera dysku to nie C:
        if sys.platform == "win32":
             # sprawdzenie czy to nie C: i czy sciezka istnieje
            if p.device.upper().startswith(('A:', 'B:')) or (len(p.device) == 3 and p.device[1:3] == ':\\' and p.device[0].upper() != 'C'):
                 if os.path.isdir(p.mountpoint):
                    removable_drives.append(p.mountpoint)
                    continue

    # usun duplikaty
    return sorted(list(set(removable_drives)))


def find_key_on_removable_drives():
    """Szuka pliku KEY_FILENAME na wszystkich wymiennych dyskach.
       Zwraca pełną ścieżkę do pierwszego znalezionego pliku lub None."""
    drives = list_removable_drives()
    for drive_path in drives:
        potential_key_path = os.path.join(drive_path, KEY_FILENAME)
        if os.path.isfile(potential_key_path):
            print(f"Znaleziono plik klucza: {potential_key_path}")
            return potential_key_path
    print("Nie znaleziono pliku klucza na żadnym wymiennym nośniku.")
    return None
